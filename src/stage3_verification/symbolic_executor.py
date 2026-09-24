"""Symbolic execution for taint chain verification.

Supports multiple backends:
1. Z3 solver (preferred)
2. Java PathFinder via jpype (optional)
3. Fallback to UNVERIFIABLE if neither available
"""

import ast
import hashlib
import importlib.util
import operator
import re
from enum import Enum
from typing import Any, Dict, List, Optional

from src.core.models import TaintChain, VerificationStatus
from src.utils.logger import get_logger

logger = get_logger()


# Check Z3 availability
try:
    import z3
    Z3_AVAILABLE = True
    logger.info("Z3 solver available for symbolic execution")
except ImportError:
    Z3_AVAILABLE = False
    logger.warning("Z3 not available, symbolic execution will be limited")


# Check JPype availability (for Java PathFinder)
try:
    JPYPE_AVAILABLE = importlib.util.find_spec("jpype") is not None
    if not JPYPE_AVAILABLE:
        raise ImportError
    logger.info("JPype available for Java PathFinder integration")
except ImportError:
    JPYPE_AVAILABLE = False
    logger.debug("JPype not available, JPF integration disabled")


class SymbolicBackend(Enum):
    """Symbolic execution backend options."""
    Z3 = "z3"
    JPF = "jpf"
    NONE = "none"


class SymbolicVariable:
    """Represents a symbolic variable in symbolic execution."""

    def __init__(self, name: str, var_type: str = "String") -> None:
        """Initialize symbolic variable.

        Args:
            name: Variable name.
            var_type: Variable type (String, int, boolean, etc.).
        """
        self.name = name
        self.var_type = var_type
        self.constraints: List[Any] = []

        if Z3_AVAILABLE:
            # Create Z3 symbolic variable based on type
            if var_type in ("int", "Integer"):
                self.z3_var = z3.Int(name)
            elif var_type in ("boolean", "Boolean"):
                self.z3_var = z3.Bool(name)
            else:  # String or unknown
                self.z3_var = z3.String(name)
        else:
            self.z3_var = None

    def add_constraint(self, constraint: Any) -> None:
        """Add a constraint to this variable.

        Args:
            constraint: Z3 constraint or string representation.
        """
        self.constraints.append(constraint)

    def __repr__(self) -> str:
        return f"SymVar({self.name}: {self.var_type}, {len(self.constraints)} constraints)"


class PathConstraints:
    """Represents path constraints for symbolic execution."""

    def __init__(self) -> None:
        """Initialize path constraints."""
        self.constraints: List[Any] = []
        self.variables: Dict[str, SymbolicVariable] = {}
        self.modeled_edges = 0
        self.expected_edges = 0
        self.integer_constants: Dict[str, int] = {}

    def add_variable(self, name: str, var_type: str = "String") -> SymbolicVariable:
        """Add a symbolic variable.

        Args:
            name: Variable name.
            var_type: Variable type.

        Returns:
            SymbolicVariable instance.
        """
        if name not in self.variables:
            self.variables[name] = SymbolicVariable(name, var_type)

        return self.variables[name]

    def add_constraint(self, constraint: Any) -> None:
        """Add a path constraint.

        Args:
            constraint: Z3 constraint or string representation.
        """
        self.constraints.append(constraint)
        logger.debug(f"Added constraint: {constraint}")

    def __repr__(self) -> str:
        return f"PathConstraints({len(self.variables)} vars, {len(self.constraints)} constraints)"


class SymbolicExecutor:
    """Symbolic execution engine for verification.

    Supports multiple backends:
    1. Z3 solver (preferred) - builds SMT constraints
    2. Java PathFinder (optional) - uses JPF if available
    3. Fallback - returns UNVERIFIABLE
    """

    def __init__(
        self,
        backend: Optional[SymbolicBackend] = None,
        timeout: int = 30
    ) -> None:
        """Initialize symbolic executor.

        Args:
            backend: Preferred backend (auto-detected if None).
            timeout: Timeout in seconds for solver.
        """
        self.timeout = timeout

        # Auto-detect backend if not specified
        if backend is None:
            if Z3_AVAILABLE:
                self.backend = SymbolicBackend.Z3
            elif JPYPE_AVAILABLE:
                self.backend = SymbolicBackend.JPF
            else:
                self.backend = SymbolicBackend.NONE
        else:
            self.backend = backend

        logger.debug(
            f"Initialized SymbolicExecutor with backend: {self.backend.value}"
        )

        if self.backend == SymbolicBackend.NONE:
            logger.warning(
                "No symbolic execution backend available. "
                "Install z3-solver for symbolic execution support."
            )

    def execute_path(
        self,
        chain: TaintChain,
        source_code: str
    ) -> VerificationStatus:
        """Execute symbolic execution on a taint chain path.

        Args:
            chain: TaintChain to verify.
            source_code: Source code containing the path.

        Returns:
            VerificationStatus indicating verification result.
        """
        logger.debug(
            f"Starting symbolic execution for {chain.source.variable_name} -> "
            f"{chain.sink.variable_name}"
        )

        if self.backend == SymbolicBackend.Z3:
            return self._execute_with_z3(chain, source_code)
        elif self.backend == SymbolicBackend.JPF:
            return self._execute_with_jpf(chain, source_code)
        else:
            logger.debug(
                "No backend available for symbolic execution, returning UNVERIFIABLE"
            )
            return VerificationStatus.UNVERIFIABLE

    def _execute_with_z3(
        self,
        chain: TaintChain,
        source_code: str
    ) -> VerificationStatus:
        """Execute symbolic execution using Z3 solver.

        Args:
            chain: TaintChain to verify.
            source_code: Source code.

        Returns:
            VerificationStatus based on satisfiability check.
        """
        if not Z3_AVAILABLE:
            logger.warning("Z3 not available")
            return VerificationStatus.UNVERIFIABLE

        logger.debug("Using Z3 solver for symbolic execution")

        try:
            # Build path constraints
            constraints = self._build_path_constraints(chain, source_code)

            if (
                not constraints.constraints
                or constraints.modeled_edges < constraints.expected_edges
            ):
                logger.debug(
                    "Symbolic execution inconclusive: "
                    f"modeled {constraints.modeled_edges}/"
                    f"{constraints.expected_edges} path edges"
                )
                return VerificationStatus.UNVERIFIABLE

            # Create Z3 solver
            solver = z3.Solver()
            solver.set("timeout", self.timeout * 1000)  # Convert to milliseconds

            # Add constraints to solver
            for constraint in constraints.constraints:
                if constraint is not None:
                    solver.add(constraint)

            # Check satisfiability
            result = solver.check()

            if result == z3.sat:
                logger.debug(
                    f"✓ Symbolic execution: {chain.source.variable_name} -> "
                    f"{chain.sink.variable_name} VERIFIED (SAT)"
                )
                return VerificationStatus.VERIFIED

            elif result == z3.unsat:
                logger.debug(
                    f"✗ Symbolic execution: {chain.source.variable_name} -> "
                    f"{chain.sink.variable_name} FALSE (UNSAT)"
                )
                return VerificationStatus.FALSE

            else:  # unknown
                logger.debug(
                    f"? Symbolic execution: {chain.source.variable_name} -> "
                    f"{chain.sink.variable_name} UNKNOWN (timeout or solver limitation)"
                )
                return VerificationStatus.UNVERIFIABLE

        except Exception:
            logger.exception(
                "Z3 symbolic execution failed for "
                f"chain={chain.id!r}, "
                f"source={chain.source.variable_name!r}, "
                f"sink={chain.sink.variable_name!r}"
            )
            return VerificationStatus.UNVERIFIABLE

    def _build_path_constraints(
        self,
        chain: TaintChain,
        source_code: str
    ) -> PathConstraints:
        """Build path constraints from taint chain.

        Args:
            chain: TaintChain containing path information.
            source_code: Source code for context.

        Returns:
            PathConstraints object with Z3 constraints.
        """
        constraints = PathConstraints()
        constraints.integer_constants = self._collect_integer_constants(source_code)

        # Add source variable as symbolic
        constraints.add_variable(
            chain.source.variable_name,
            "String"  # Most taint sources are strings
        )

        # Add sink variable as symbolic
        constraints.add_variable(
            chain.sink.variable_name,
            "String"
        )

        if not Z3_AVAILABLE:
            return constraints

        # Extract path from chain
        path = chain.path if hasattr(chain, 'path') else []
        constraints.expected_edges = max(0, len(path) - 1)

        # Build constraints from path
        for i in range(len(path) - 1):
            current_node = path[i]
            next_node = path[i + 1]
            current = current_node.variable_name if hasattr(current_node, 'variable_name') else str(current_node)
            next_var = next_node.variable_name if hasattr(next_node, 'variable_name') else str(next_node)

            # Find the statement connecting current -> next
            snippets = [
                getattr(next_node, "code_snippet", ""),
                getattr(current_node, "code_snippet", ""),
            ]
            stmt = self._find_statement_for_edge(
                source_code, current, next_var, snippets=snippets
            )

            if stmt:
                constraint = self._extract_constraint_from_statement(
                    stmt,
                    current,
                    next_var,
                    constraints
                )
                if constraint is not None:
                    constraints.add_constraint(constraint)
                    constraints.modeled_edges += 1

        logger.debug(f"Built path constraints: {constraints}")
        return constraints

    def _find_statement_for_edge(
        self,
        source_code: str,
        var1: str,
        var2: str,
        *,
        snippets: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Find statement that connects two variables.

        Args:
            source_code: Source code to search.
            var1: First variable.
            var2: Second variable.

        Returns:
            Statement string or None.
        """
        lines = [*(snippets or []), *source_code.split('\n')]

        for line in lines:
            if not line:
                continue
            # Assignment/call/return evidence must mention the exact Java
            # identifiers. Substring matching joined unrelated names such as
            # `id` and `identity` and produced misleading SAT results.
            has_source = re.search(
                rf"(?<![A-Za-z0-9_$]){re.escape(var1)}(?![A-Za-z0-9_$])",
                line,
            )
            has_target = re.search(
                rf"(?<![A-Za-z0-9_$]){re.escape(var2)}(?![A-Za-z0-9_$])",
                line,
            )
            return_flow = var2 == "return_value" and re.search(
                rf"\breturn\b[^;]*\b{re.escape(var1)}\b", line
            )
            if (has_source and has_target) or return_flow:
                return line.strip()

        return None

    def _extract_constraint_from_statement(
        self,
        stmt: str,
        source_var: str,
        dest_var: str,
        constraints: PathConstraints
    ) -> Optional[Any]:
        """Extract Z3 constraint from a statement.

        Args:
            stmt: Statement string.
            source_var: Source variable name.
            dest_var: Destination variable name.
            constraints: PathConstraints object.

        Returns:
            Z3 constraint or None.
        """
        if not Z3_AVAILABLE:
            return None

        # Get or create symbolic variables
        src = constraints.add_variable(source_var, "String")
        dst = constraints.add_variable(dest_var, "String")

        if src.z3_var is None or dst.z3_var is None:
            return None

        assignment = re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(dest_var)}\s*=\s*(.+?);?\s*$",
            stmt,
        )
        if assignment:
            rhs = assignment.group(1).rstrip(";").strip()
            ternary = self._split_ternary(rhs)
            if ternary is not None:
                condition, true_branch, false_branch = ternary
                condition_value = self._evaluate_integer_condition(
                    condition, constraints.integer_constants
                )
                if condition_value is not None:
                    selected = true_branch if condition_value else false_branch
                    if (
                        self._mentions_identifier(rhs, source_var)
                        and not self._mentions_identifier(selected, source_var)
                    ):
                        # The graph edge exists syntactically, but its tainted
                        # branch is impossible under compile-time constants.
                        return z3.BoolVal(False)
                    rhs = selected.strip()
            if re.fullmatch(re.escape(source_var), rhs):
                return dst.z3_var == src.z3_var

        # String concatenation: dest = source + something
        if assignment and '+' in rhs and self._mentions_identifier(rhs, source_var):
            # For string concat, dest contains source
            if isinstance(src.z3_var, z3.SeqRef):
                return z3.Contains(dst.z3_var, src.z3_var)

        # A syntactically proven transformation/call preserves a dependency
        # unless Stage 1 identified an effective sanitizer. Model its value as
        # an uninterpreted function rather than pretending to understand the
        # Java library implementation.
        if assignment and re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(source_var)}(?![A-Za-z0-9_$])",
            rhs,
        ):
            function_name = "flow_" + hashlib.sha256(
                stmt.encode("utf-8")
            ).hexdigest()[:16]
            opaque = z3.Function(
                function_name, z3.StringSort(), z3.StringSort()
            )
            return dst.z3_var == opaque(src.z3_var)

        if dest_var == "return_value" and re.search(
            rf"\breturn\b[^;]*\b{re.escape(source_var)}\b", stmt
        ):
            return dst.z3_var == src.z3_var

        if re.search(
            rf"\b[A-Za-z_$][\w$]*\s*\([^;]*\b{re.escape(source_var)}\b[^;]*\)",
            stmt,
        ) and re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(dest_var)}(?![A-Za-z0-9_$])",
            stmt,
        ):
            function_name = "call_" + hashlib.sha256(
                stmt.encode("utf-8")
            ).hexdigest()[:16]
            opaque = z3.Function(
                function_name, z3.StringSort(), z3.StringSort()
            )
            return dst.z3_var == opaque(src.z3_var)

        # Conditional statements
        if 'if' in stmt:
            # Extract condition
            match = re.search(r'if\s*\(([^)]+)\)', stmt)
            if match:
                condition = match.group(1)
                return self._parse_condition(condition, constraints)

        return None

    @staticmethod
    def _mentions_identifier(expression: str, identifier: str) -> bool:
        return bool(re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(identifier)}(?![A-Za-z0-9_$])",
            expression,
        ))

    @staticmethod
    def _split_ternary(expression: str) -> Optional[tuple[str, str, str]]:
        """Split a simple Java ternary; nested ternaries stay inconclusive."""
        if expression.count("?") != 1 or expression.count(":") != 1:
            return None
        condition, question, remainder = expression.partition("?")
        true_branch, colon, false_branch = remainder.partition(":")
        if not question or not colon:
            return None
        if not condition.strip() or not true_branch.strip() or not false_branch.strip():
            return None
        return condition.strip(), true_branch.strip(), false_branch.strip()

    @classmethod
    def _collect_integer_constants(cls, source_code: str) -> Dict[str, int]:
        """Collect local integer constants using a restricted AST evaluator."""
        declarations = re.findall(
            r"\b(?:byte|short|int|long|Integer|Long)\s+"
            r"([A-Za-z_$][\w$]*)\s*=\s*([^;]+);",
            source_code,
        )
        values: Dict[str, int] = {}
        pending = list(declarations)
        while pending:
            unresolved = []
            changed = False
            for name, expression in pending:
                value = cls._safe_integer_expression(expression, values)
                if value is None:
                    unresolved.append((name, expression))
                    continue
                values[name] = value
                changed = True
            if not changed:
                break
            pending = unresolved
        return values

    @classmethod
    def _evaluate_integer_condition(
        cls, condition: str, constants: Dict[str, int]
    ) -> Optional[bool]:
        condition = condition.strip()
        while condition.startswith("(") and condition.endswith(")"):
            condition = condition[1:-1].strip()
        match = re.fullmatch(r"(.+?)\s*(>=|<=|==|!=|>|<)\s*(.+)", condition)
        if not match:
            return None
        left = cls._safe_integer_expression(match.group(1), constants)
        right = cls._safe_integer_expression(match.group(3), constants)
        if left is None or right is None:
            return None
        comparisons = {
            ">": operator.gt,
            "<": operator.lt,
            ">=": operator.ge,
            "<=": operator.le,
            "==": operator.eq,
            "!=": operator.ne,
        }
        return comparisons[match.group(2)](left, right)

    @staticmethod
    def _safe_integer_expression(
        expression: str, constants: Dict[str, int]
    ) -> Optional[int]:
        """Evaluate arithmetic made only from integer literals and constants."""
        expression = re.sub(r"(?<=\d)[lL]\b", "", expression.strip())
        try:
            root = ast.parse(expression, mode="eval")
        except SyntaxError:
            return None

        binary_ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: lambda left, right: int(left / right),
            ast.FloorDiv: lambda left, right: int(left / right),
            ast.Mod: operator.mod,
        }
        unary_ops = {ast.UAdd: operator.pos, ast.USub: operator.neg}

        def evaluate(node: ast.AST) -> int:
            if isinstance(node, ast.Expression):
                return evaluate(node.body)
            if isinstance(node, ast.Constant) and type(node.value) is int:
                return node.value
            if isinstance(node, ast.Name) and node.id in constants:
                return constants[node.id]
            if isinstance(node, ast.BinOp) and type(node.op) in binary_ops:
                return binary_ops[type(node.op)](
                    evaluate(node.left), evaluate(node.right)
                )
            if isinstance(node, ast.UnaryOp) and type(node.op) in unary_ops:
                return unary_ops[type(node.op)](evaluate(node.operand))
            raise ValueError("unsupported integer expression")

        try:
            return evaluate(root)
        except (ArithmeticError, ValueError):
            return None

    def _parse_condition(
        self,
        condition: str,
        constraints: PathConstraints
    ) -> Optional[Any]:
        """Parse a condition into Z3 constraint.

        Args:
            condition: Condition string (e.g., "x > 0").
            constraints: PathConstraints object.

        Returns:
            Z3 constraint or None.
        """
        if not Z3_AVAILABLE:
            return None

        # Simple comparisons
        if '>' in condition:
            parts = condition.split('>')
            if len(parts) == 2:
                var_name = parts[0].strip()
                value = parts[1].strip()
                var = constraints.add_variable(var_name, "int")
                if var.z3_var is not None:
                    try:
                        return var.z3_var > int(value)
                    except ValueError:
                        pass

        elif '<' in condition:
            parts = condition.split('<')
            if len(parts) == 2:
                var_name = parts[0].strip()
                value = parts[1].strip()
                var = constraints.add_variable(var_name, "int")
                if var.z3_var is not None:
                    try:
                        return var.z3_var < int(value)
                    except ValueError:
                        pass

        elif '==' in condition:
            parts = condition.split('==')
            if len(parts) == 2:
                var_name = parts[0].strip()
                value = parts[1].strip()
                var = constraints.add_variable(var_name, "String")
                if var.z3_var is not None:
                    return var.z3_var == z3.StringVal(value.strip('"'))

        # For complex conditions, return None (conservative)
        return None

    def _execute_with_jpf(
        self,
        chain: TaintChain,
        source_code: str
    ) -> VerificationStatus:
        """Execute symbolic execution using Java PathFinder.

        Args:
            chain: TaintChain to verify.
            source_code: Source code.

        Returns:
            VerificationStatus (currently returns UNVERIFIABLE).
        """
        if not JPYPE_AVAILABLE:
            logger.warning("JPype not available, cannot use Java PathFinder")
            return VerificationStatus.UNVERIFIABLE

        logger.warning(
            "Java PathFinder integration not yet implemented. "
            "Returning UNVERIFIABLE. Use Z3 backend for symbolic execution."
        )

        # TODO: Implement JPF integration
        # 1. Start JVM with jpype.startJVM()
        # 2. Load JPF classes
        # 3. Configure JPF to analyze the code
        # 4. Run JPF symbolic execution
        # 5. Parse JPF results
        # 6. Return verification status

        return VerificationStatus.UNVERIFIABLE

    def get_backend_info(self) -> Dict[str, Any]:
        """Get information about symbolic execution backend.

        Returns:
            Dictionary with backend information.
        """
        return {
            "backend": self.backend.value,
            "z3_available": Z3_AVAILABLE,
            "jpype_available": JPYPE_AVAILABLE,
            "timeout": self.timeout,
        }
