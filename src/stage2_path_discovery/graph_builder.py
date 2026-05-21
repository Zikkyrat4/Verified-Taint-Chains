"""Enhanced data flow graph builder with improved variable tracking and control flow analysis."""

import re
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from src.core.models import Source, Sink
from src.core.types import DataFlowPath, Variables
from src.utils.logger import get_logger

logger = get_logger()


class VariableTracker:
    """Tracks variable types and definitions throughout code."""

    def __init__(self) -> None:
        """Initialize variable tracker."""
        self.declarations: Dict[str, str] = {}  # var_name -> type
        self.definitions: Dict[str, Set[str]] = {}  # var_name -> set of line numbers
        self.uses: Dict[str, Set[str]] = {}  # var_name -> set of contexts

    def add_declaration(self, var_name: str, var_type: str) -> None:
        """Record a variable declaration.

        Args:
            var_name: Variable name.
            var_type: Variable type (String, int, etc.).
        """
        self.declarations[var_name] = var_type
        logger.debug(f"Declared variable: {var_name} of type {var_type}")

    def add_definition(self, var_name: str, line_num: str) -> None:
        """Record where a variable is defined/assigned.

        Args:
            var_name: Variable name.
            line_num: Line number or context identifier.
        """
        if var_name not in self.definitions:
            self.definitions[var_name] = set()
        self.definitions[var_name].add(line_num)

    def add_use(self, var_name: str, context: str) -> None:
        """Record a use of the variable.

        Args:
            var_name: Variable name.
            context: Context of use (function name, line, etc.).
        """
        if var_name not in self.uses:
            self.uses[var_name] = set()
        self.uses[var_name].add(context)

    def get_type(self, var_name: str) -> Optional[str]:
        """Get the type of a variable.

        Args:
            var_name: Variable name.

        Returns:
            Type string or None if unknown.
        """
        return self.declarations.get(var_name)

    def is_untrusted_type(self, var_type: Optional[str]) -> bool:
        """Check if a type is typically untrusted.

        Args:
            var_type: Type string.

        Returns:
            True if type suggests untrusted data.
        """
        if not var_type:
            return False

        untrusted_patterns = {
            "HttpServletRequest",
            "HttpRequest",
            "InputStream",
            "Reader",
            "Scanner",
            "BufferedReader",
            "Socket",
            "URLConnection",
            "String",  # From user input
        }

        return any(pattern in var_type for pattern in untrusted_patterns)


class EnhancedGraphBuilder:
    """Enhanced data flow graph builder with improved variable tracking and control flow.

    Improvements over SimpleGraphBuilder:
    - Maintains variable type information
    - Tracks assignments more accurately
    - Includes control flow edges
    - Better handling of method calls and returns
    - Variable scope awareness
    """

    def __init__(self) -> None:
        """Initialize the enhanced graph builder."""
        self.variable_tracker = VariableTracker()
        logger.debug("Initialized EnhancedGraphBuilder")

    def build_graph(
        self, source_code: str, sources: List[Source], sinks: List[Sink]
    ) -> nx.DiGraph:
        """Build an enhanced data flow graph from source code.

        Creates a directed graph with:
        - Data flow edges (variable assignments, method calls)
        - Control flow edges (if/else, loops)
        - Edge metadata (type, confidence)

        Args:
            source_code: Java source code to analyze.
            sources: List of identified source nodes.
            sinks: List of identified sink nodes.

        Returns:
            NetworkX DiGraph representing data and control flow.
        """
        graph = nx.DiGraph()

        # Extract variable declarations and types
        self._extract_declarations(source_code)
        logger.debug(f"Extracted {len(self.variable_tracker.declarations)} variable declarations")

        # Extract all variables from code
        variables = self._extract_variables(source_code)
        logger.debug(f"Extracted {len(variables)} unique variables")

        # Add source nodes
        for source in sources:
            graph.add_node(
                source.variable_name,
                type="source",
                source=source,
                var_type=self.variable_tracker.get_type(source.variable_name),
                confidence=source.confidence,
            )

        # Add sink nodes
        for sink in sinks:
            graph.add_node(
                sink.variable_name,
                type="sink",
                sink=sink,
                var_type=self.variable_tracker.get_type(sink.variable_name),
                confidence=sink.confidence,
            )

        # Add other variables as intermediate nodes
        for var in variables:
            if var not in graph:
                graph.add_node(
                    var,
                    type="intermediate",
                    var_type=self.variable_tracker.get_type(var),
                )

        # Extract and add data flow edges
        data_flow_edges = self._extract_data_flows(source_code)
        logger.debug(f"Extracted {len(data_flow_edges)} data flow edges")

        for source_var, target_var, metadata in data_flow_edges:
            if source_var in graph and target_var in graph:
                graph.add_edge(
                    source_var,
                    target_var,
                    edge_type="data_flow",
                    **metadata,
                )

        # Extract and add control flow edges
        control_flow_edges = self._extract_control_flows(source_code)
        logger.debug(f"Extracted {len(control_flow_edges)} control flow edges")

        for source_var, target_var, condition in control_flow_edges:
            if source_var in graph and target_var in graph:
                # Add control flow edge if not already a data flow edge
                if not graph.has_edge(source_var, target_var):
                    graph.add_edge(
                        source_var,
                        target_var,
                        edge_type="control_flow",
                        condition=condition,
                    )

        logger.info(
            f"Built enhanced graph with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges"
        )

        return graph

    def _extract_declarations(self, code: str) -> None:
        """Extract variable declarations with types.

        Args:
            code: Java source code.
        """
        # Pattern: type varName or type varName = value
        # Matches: String name = "test"; int count = 0; etc.
        declaration_pattern = r"(String|int|long|double|float|boolean|List|Map|Set|ResultSet|HttpServletRequest|InputStream|Reader|Scanner|BufferedReader|Socket|URLConnection)\s+([a-zA-Z_][a-zA-Z0-9_]*)"

        for match in re.finditer(declaration_pattern, code):
            var_type = match.group(1)
            var_name = match.group(2)
            self.variable_tracker.add_declaration(var_name, var_type)

    def _extract_variables(self, code: str) -> Variables:
        """Extract variable names from Java code using regex.

        Args:
            code: Java source code.

        Returns:
            Set of unique variable names found.
        """
        pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b"
        variables: Variables = set()

        for match in re.finditer(pattern, code):
            var = match.group(1)

            # Filter out Java keywords
            if not self._is_keyword(var) and len(var) > 1:
                variables.add(var)

        logger.debug(f"Found {len(variables)} variables (after filtering keywords)")
        return variables

    def _extract_data_flows(self, code: str) -> List[Tuple[str, str, Dict]]:
        """Extract data flow relationships from code.

        Identifies:
        - Simple assignments: var1 = var2
        - Compound assignments: var1 = var2 + var3
        - Method calls: var1 = method(var2)
        - Field accesses: var1 = obj.field

        Args:
            code: Java source code.

        Returns:
            List of (source_var, target_var, metadata) tuples.
        """
        edges: List[Tuple[str, str, Dict]] = []

        # Pattern 1: Simple assignment var1 = var2 or var1 = constant
        # See note in SimpleGraphBuilder: excluding ``=`` from the RHS char
        # class drops every assignment whose RHS contains a comparison or
        # ternary (``new File(dir, id == null ? a : b)``, ``var ok = (a != b)``,
        # ``String s = (x <= 5) ? "low" : "high"``). Allow ``=`` in the RHS.
        # The optional ``[]`` after the name captures C-style array
        # declarations ``String cmdArgs[] = {...}`` whose bracket would
        # otherwise sit between the name and ``=`` and skip the whole match.
        assignment_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\s*\])?\s*=\s*([^;]+);"

        for match in re.finditer(assignment_pattern, code):
            target_var = match.group(1).strip()
            source_expr = match.group(2).strip()

            # Extract variables used on the right side
            var_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)"
            for var_match in re.finditer(var_pattern, source_expr):
                source_var = var_match.group(1)

                # Skip keywords and self-loops
                if not self._is_keyword(source_var) and source_var != target_var:
                    # Determine flow type
                    flow_type = self._determine_flow_type(source_expr, source_var)

                    edges.append(
                        (source_var, target_var, {"flow_type": flow_type})
                    )

        # Pattern 2: Method calls and returns
        method_call_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*?)\)"

        for match in re.finditer(method_call_pattern, code):
            target_var = match.group(1)
            method_name = match.group(2)
            params = match.group(3)

            # Extract parameters as source variables
            for param in params.split(","):
                param = param.strip()
                if param and not self._is_keyword(param):
                    edges.append(
                        (param, target_var, {"flow_type": "method_call", "method": method_name})
                    )

        # Pattern 3: obj.method() — data flows from object through method call
        method_chain_pattern = r'\b([a-zA-Z_]\w+)\.([a-zA-Z_]\w+)\s*\('
        for match in re.finditer(method_chain_pattern, code):
            obj = match.group(1)
            method = match.group(2)
            if not self._is_keyword(obj) and len(obj) > 1 and not self._is_keyword(method) and len(method) > 1:
                edges.append((obj, method, {"flow_type": "method_chain"}))

        # Pattern 4: throw new ExceptionType(args) — variables in args flow to exception
        throw_pattern = r'throw\s+new\s+(\w+)\s*\((.+?)\)\s*;'
        for match in re.finditer(throw_pattern, code):
            exception_type = match.group(1)
            args = match.group(2)
            for var_match in re.finditer(r'\b([a-zA-Z_]\w+)\b', args):
                var = var_match.group(1)
                if not self._is_keyword(var) and len(var) > 1:
                    edges.append((var, exception_type, {"flow_type": "throw_arg"}))

        # Pattern 5: return expr; — variables flow to return
        return_pattern = r'return\s+([^;]+);'
        for match in re.finditer(return_pattern, code):
            expr = match.group(1).strip()
            for var_match in re.finditer(r'\b([a-zA-Z_]\w+)\b', expr):
                var = var_match.group(1)
                if not self._is_keyword(var) and len(var) > 1:
                    edges.append((var, "return_value", {"flow_type": "return"}))

        # Pattern 6: obj.method(arg1, arg2) — args flow to obj
        method_arg_pattern = r'(\w+)\.\w+\s*\(([^)]+)\)'
        for match in re.finditer(method_arg_pattern, code):
            receiver = match.group(1)
            args = match.group(2)
            if self._is_keyword(receiver) or len(receiver) <= 1:
                continue
            for var_match in re.finditer(r'\b([a-zA-Z_]\w+)\b', args):
                var = var_match.group(1)
                if not self._is_keyword(var) and var != receiver and len(var) > 1:
                    edges.append((var, receiver, {"flow_type": "method_arg"}))

        logger.debug(f"Found {len(edges)} data flow edges")
        return edges

    def _extract_control_flows(self, code: str) -> List[Tuple[str, str, str]]:
        """Extract control flow relationships from code.

        Identifies:
        - If/else conditions
        - Loop iterations
        - Conditional expressions

        Args:
            code: Java source code.

        Returns:
            List of (source_var, target_var, condition) tuples.
        """
        edges: List[Tuple[str, str, str]] = []

        # Pattern 1: if (var) ... or if (condition with var)
        if_pattern = r"if\s*\(\s*([^)]+)\s*\)\s*\{"

        for match in re.finditer(if_pattern, code):
            condition = match.group(1).strip()
            # Extract variables from condition
            var_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)"
            for var_match in re.finditer(var_pattern, condition):
                var = var_match.group(1)
                if not self._is_keyword(var):
                    # Control flow from condition variable
                    edges.append((var, var, f"condition: {condition}"))

        # Pattern 2: Loops (for, while)
        loop_pattern = r"(for|while)\s*\(\s*([^)]+)\s*\)\s*\{"

        for match in re.finditer(loop_pattern, code):
            loop_type = match.group(1)
            loop_condition = match.group(2).strip()
            # Extract loop variables
            var_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)"
            for var_match in re.finditer(var_pattern, loop_condition):
                var = var_match.group(1)
                if not self._is_keyword(var):
                    edges.append((var, var, f"{loop_type}: {loop_condition}"))

        logger.debug(f"Found {len(edges)} control flow edges")
        return edges

    def _determine_flow_type(self, expression: str, source_var: str) -> str:
        """Determine the type of data flow.

        Args:
            expression: The right-hand side expression.
            source_var: The source variable name.

        Returns:
            Flow type string ("direct", "arithmetic", "concatenation", "method_call").
        """
        # Check for direct assignment
        if expression.strip() == source_var:
            return "direct"
        # Check for string concatenation
        elif "+" in expression:
            return "concatenation"
        # Check for arithmetic
        elif any(op in expression for op in ["-", "*", "/", "%"]):
            return "arithmetic"
        # Check for method call
        elif "(" in expression and ")" in expression:
            return "method_call"
        else:
            return "other"

    @staticmethod
    def _is_keyword(word: str) -> bool:
        """Check if word is a Java keyword.

        Args:
            word: Word to check.

        Returns:
            True if word is a Java keyword.
        """
        keywords = {
            "public",
            "private",
            "protected",
            "static",
            "final",
            "class",
            "interface",
            "void",
            "int",
            "String",
            "boolean",
            "double",
            "float",
            "long",
            "short",
            "byte",
            "char",
            "if",
            "else",
            "for",
            "while",
            "return",
            "new",
            "null",
            "true",
            "false",
            "this",
            "super",
            "import",
            "package",
            "try",
            "catch",
            "finally",
            "throw",
            "throws",
            "default",
            "case",
            "switch",
            "break",
            "continue",
            "synchronized",
            "volatile",
            "transient",
            "abstract",
            "native",
            "strictfp",
            "List",
            "Map",
            "Set",
            "Collection",
            "ArrayList",
            "HashMap",
            "HashSet",
        }
        return word in keywords
