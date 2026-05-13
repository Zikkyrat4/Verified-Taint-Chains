"""Java AST parsing using tree-sitter for accurate code structure analysis."""

from typing import Any, Dict, List, Optional
import re

try:
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser
    JAVA_LANGUAGE = Language(tsjava.language())
    TREE_SITTER_AVAILABLE = True
except (ImportError, Exception):
    TREE_SITTER_AVAILABLE = False
    JAVA_LANGUAGE = None

from src.utils.logger import get_logger

logger = get_logger()


class JavaASTParser:
    """Parse Java code using tree-sitter for accurate AST analysis.

    Uses the tree-sitter parser to extract precise information about:
    - Class declarations
    - Method/function definitions
    - Method parameters and return types
    - Code structure and organization
    - Data flow edges (assignments, method calls, returns, throws, field accesses)
    """

    def __init__(self) -> None:
        """Initialize tree-sitter parser for Java.

        Raises:
            RuntimeError: If tree-sitter Java library is not available.
        """
        if not TREE_SITTER_AVAILABLE or JAVA_LANGUAGE is None:
            logger.warning(
                "tree-sitter not available, falling back to regex parsing"
            )
            self.parser = None
            return

        try:
            self.parser = Parser()
            self.parser.language = JAVA_LANGUAGE
            logger.info("Initialized tree-sitter Java parser")

        except Exception as e:
            logger.warning(f"Failed to initialize tree-sitter: {str(e)}")
            logger.info("Will fall back to regex-based parsing")
            self.parser = None

    def parse(self, source_code: str) -> Dict[str, Any]:
        """Parse Java source code to AST.

        Args:
            source_code: Java source code as string.

        Returns:
            Dictionary containing parsed AST structure.
        """
        if self.parser is None:
            logger.debug("Using fallback regex-based parsing")
            return self._parse_with_regex(source_code)

        try:
            tree = self.parser.parse(source_code.encode("utf-8"))

            return {
                "root": tree.root_node,
                "source": source_code,
                "size": len(source_code),
                "method": "tree-sitter",
            }

        except Exception as e:
            logger.warning(f"AST parsing failed: {str(e)}, falling back to regex")
            return self._parse_with_regex(source_code)

    def extract_functions(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract all methods/functions from Java code.

        Args:
            source_code: Java source code.

        Returns:
            List of function definitions with metadata.
        """
        if self.parser is None:
            logger.debug("Using regex-based function extraction")
            return self._extract_functions_regex(source_code)

        functions: List[Dict[str, Any]] = []

        try:
            tree = self.parser.parse(source_code.encode("utf-8"))

            # Query for method declarations
            method_query = '(method_declaration (modifiers)? (type_identifier) @return_type (method_name) @method_name (formal_parameters) @params (block) @body)'

            # Traverse tree to find method declarations
            self._traverse_and_extract_methods(
                tree.root_node, source_code, functions
            )

            logger.debug(f"Extracted {len(functions)} functions using tree-sitter")

        except Exception as e:
            logger.warning(f"Function extraction failed: {str(e)}")
            return self._extract_functions_regex(source_code)

        return functions

    def extract_classes(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract all class declarations from Java code.

        Args:
            source_code: Java source code.

        Returns:
            List of class definitions with metadata.
        """
        if self.parser is None:
            logger.debug("Using regex-based class extraction")
            return self._extract_classes_regex(source_code)

        classes: List[Dict[str, Any]] = []

        try:
            tree = self.parser.parse(source_code.encode("utf-8"))

            # Traverse tree to find class declarations
            self._traverse_and_extract_classes(
                tree.root_node, source_code, classes
            )

            logger.debug(f"Extracted {len(classes)} classes using tree-sitter")

        except Exception as e:
            logger.warning(f"Class extraction failed: {str(e)}")
            return self._extract_classes_regex(source_code)

        return classes

    def extract_data_flows(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract data flow edges from Java code using AST.

        Walks the tree-sitter AST to extract:
        - Assignment expressions (var = expr) -> edges from RHS variables to LHS
        - Method invocations (obj.method(arg)) -> edges from args to receiver
        - Return statements -> edges from returned variables
        - Throw statements -> edges from thrown expression variables
        - Field accesses (obj.field) -> edges from obj to field

        Falls back to regex-based extraction if tree-sitter is unavailable.

        Args:
            source_code: Java source code.

        Returns:
            List of dicts with keys: from_var, to_var, flow_type, line.
        """
        if self.parser is None:
            return self._extract_data_flows_regex(source_code)

        try:
            tree = self.parser.parse(source_code.encode("utf-8"))
            flows: List[Dict[str, Any]] = []
            self._traverse_data_flows(tree.root_node, source_code, flows)
            logger.debug(f"Extracted {len(flows)} data flows using tree-sitter AST")
            return flows
        except Exception as e:
            logger.warning(f"AST data flow extraction failed: {str(e)}, falling back to regex")
            return self._extract_data_flows_regex(source_code)

    def _traverse_data_flows(
        self, node: Any, source_code: str, flows: List[Dict[str, Any]]
    ) -> None:
        """Recursively traverse AST nodes and extract data flow edges.

        Args:
            node: Current tree-sitter AST node.
            source_code: Original source code.
            flows: Accumulator list for discovered flows.
        """
        try:
            node_type = node.type

            if node_type == "local_variable_declaration":
                self._extract_local_var_flows(node, source_code, flows)
            elif node_type == "assignment_expression":
                self._extract_assignment_flows(node, source_code, flows)
            elif node_type == "method_invocation":
                self._extract_method_invocation_flows(node, source_code, flows)
            elif node_type == "return_statement":
                self._extract_return_flows(node, source_code, flows)
            elif node_type == "throw_statement":
                self._extract_throw_flows(node, source_code, flows)
            elif node_type == "field_access":
                self._extract_field_access_flows(node, source_code, flows)

            for child in node.children:
                self._traverse_data_flows(child, source_code, flows)
        except Exception as e:
            logger.debug(f"Error traversing data flow node: {str(e)}")

    def _extract_identifiers(self, node: Any, source_code: str) -> List[str]:
        """Extract all identifier names from a subtree.

        Args:
            node: AST node to search within.
            source_code: Original source code.

        Returns:
            List of identifier name strings.
        """
        identifiers: List[str] = []
        if node.type == "identifier":
            text = self._get_node_text(node, source_code)
            if text:
                identifiers.append(text)
        for child in node.children:
            identifiers.extend(self._extract_identifiers(child, source_code))
        return identifiers

    def _extract_local_var_flows(
        self, node: Any, source_code: str, flows: List[Dict[str, Any]]
    ) -> None:
        """Extract flows from local variable declarations (type var = expr)."""
        for child in node.children:
            if child.type == "variable_declarator":
                lhs_name = None
                rhs_node = None
                for vc in child.children:
                    if vc.type == "identifier" and lhs_name is None:
                        lhs_name = self._get_node_text(vc, source_code)
                    elif vc.type == "=":
                        continue
                    elif lhs_name is not None and vc.type not in ("identifier", "="):
                        rhs_node = vc
                    elif vc.type == "identifier" and lhs_name is not None:
                        # second identifier could be the initializer
                        rhs_node = vc

                if lhs_name and rhs_node:
                    rhs_vars = self._extract_identifiers(rhs_node, source_code)
                    line = node.start_point[0] + 1
                    for rv in rhs_vars:
                        if rv != lhs_name:
                            flows.append({
                                "from_var": rv,
                                "to_var": lhs_name,
                                "flow_type": "assignment",
                                "line": line,
                            })

    def _extract_assignment_flows(
        self, node: Any, source_code: str, flows: List[Dict[str, Any]]
    ) -> None:
        """Extract flows from assignment expressions (var = expr)."""
        children = node.children
        if len(children) >= 3:
            lhs = children[0]
            rhs = children[2]
            lhs_name = self._get_node_text(lhs, source_code)
            rhs_vars = self._extract_identifiers(rhs, source_code)
            line = node.start_point[0] + 1
            for rv in rhs_vars:
                if rv != lhs_name:
                    flows.append({
                        "from_var": rv,
                        "to_var": lhs_name,
                        "flow_type": "assignment",
                        "line": line,
                    })

    def _extract_root_receiver(self, node: Any, source_code: str) -> Optional[str]:
        """Extract the root receiver identifier from a (possibly chained) method invocation.

        For ``response.getWriter().write(bio)``, the tree-sitter AST nests
        the ``response.getWriter()`` call as the first child of the outer
        ``.write(...)`` invocation.  This helper walks down through nested
        ``method_invocation`` and ``field_access`` nodes until it reaches a
        plain ``identifier``.

        Args:
            node: AST node that is expected to be a receiver expression.
            source_code: Original source code for text extraction.

        Returns:
            Root receiver identifier string, or *None* if not found.
        """
        if node.type == "identifier":
            return self._get_node_text(node, source_code)
        if node.type == "field_access":
            # field_access children: object . field — take the object
            for child in node.children:
                if child.type == "identifier":
                    return self._get_node_text(child, source_code)
            return self._get_node_text(node, source_code)
        if node.type == "method_invocation":
            # Recurse into the first meaningful child
            for child in node.children:
                if child.type in ("identifier", "field_access", "method_invocation"):
                    result = self._extract_root_receiver(child, source_code)
                    if result:
                        return result
        return None

    def _extract_method_invocation_flows(
        self, node: Any, source_code: str, flows: List[Dict[str, Any]]
    ) -> None:
        """Extract flows from method invocations (obj.method(args)).

        Handles chained calls like ``response.getWriter().write(bio)``
        by recursively extracting the root receiver (``response``).
        """
        line = node.start_point[0] + 1
        # Find the receiver and argument list
        receiver = None
        argument_list = None
        for child in node.children:
            if child.type in ("identifier", "field_access", "method_invocation") and receiver is None:
                receiver = self._extract_root_receiver(child, source_code)
            elif child.type == "argument_list":
                argument_list = child

        if argument_list and receiver:
            arg_vars = self._extract_identifiers(argument_list, source_code)
            for av in arg_vars:
                if av != receiver:
                    flows.append({
                        "from_var": av,
                        "to_var": receiver,
                        "flow_type": "method_arg",
                        "line": line,
                    })

    def _extract_return_flows(
        self, node: Any, source_code: str, flows: List[Dict[str, Any]]
    ) -> None:
        """Extract flows from return statements."""
        line = node.start_point[0] + 1
        ret_vars = self._extract_identifiers(node, source_code)
        for rv in ret_vars:
            flows.append({
                "from_var": rv,
                "to_var": "return_value",
                "flow_type": "return",
                "line": line,
            })

    def _extract_throw_flows(
        self, node: Any, source_code: str, flows: List[Dict[str, Any]]
    ) -> None:
        """Extract flows from throw statements."""
        line = node.start_point[0] + 1
        # Find the object_creation_expression inside throw
        for child in node.children:
            if child.type == "object_creation_expression":
                # Get exception type name
                exc_type = None
                for cc in child.children:
                    if cc.type == "type_identifier":
                        exc_type = self._get_node_text(cc, source_code)
                    elif cc.type == "argument_list":
                        arg_vars = self._extract_identifiers(cc, source_code)
                        target = exc_type if exc_type else "exception"
                        for av in arg_vars:
                            flows.append({
                                "from_var": av,
                                "to_var": target,
                                "flow_type": "throw_arg",
                                "line": line,
                            })

    def _extract_field_access_flows(
        self, node: Any, source_code: str, flows: List[Dict[str, Any]]
    ) -> None:
        """Extract flows from field accesses (obj.field)."""
        children = node.children
        if len(children) >= 3:
            obj_node = children[0]
            field_node = children[2]
            obj_name = self._get_node_text(obj_node, source_code)
            field_name = self._get_node_text(field_node, source_code)
            if obj_name and field_name:
                line = node.start_point[0] + 1
                flows.append({
                    "from_var": obj_name,
                    "to_var": field_name,
                    "flow_type": "field_access",
                    "line": line,
                })

    def _extract_data_flows_regex(self, source_code: str) -> List[Dict[str, Any]]:
        """Fallback regex-based data flow extraction.

        Uses the same patterns as EnhancedGraphBuilder for consistency.

        Args:
            source_code: Java source code.

        Returns:
            List of data flow dicts.
        """
        flows: List[Dict[str, Any]] = []
        lines = source_code.split("\n")

        java_keywords = {
            "public", "private", "protected", "static", "final", "class",
            "interface", "void", "int", "String", "boolean", "double",
            "float", "long", "short", "byte", "char", "if", "else", "for",
            "while", "return", "new", "null", "true", "false", "this",
            "super", "import", "package", "try", "catch", "finally",
            "throw", "throws", "List", "Map", "Set",
        }

        def _is_keyword(word: str) -> bool:
            return word in java_keywords

        # Assignment pattern
        assignment_pattern = r"([a-zA-Z_]\w*)\s*=\s*([^;=]+);"
        for i, line in enumerate(lines, 1):
            for match in re.finditer(assignment_pattern, line):
                target = match.group(1).strip()
                source_expr = match.group(2).strip()
                for var_match in re.finditer(r"\b([a-zA-Z_]\w+)\b", source_expr):
                    var = var_match.group(1)
                    if not _is_keyword(var) and var != target:
                        flows.append({
                            "from_var": var,
                            "to_var": target,
                            "flow_type": "assignment",
                            "line": i,
                        })

        # Method chain pattern: obj.method()
        method_chain_pattern = r"\b([a-zA-Z_]\w+)\.([a-zA-Z_]\w+)\s*\("
        for i, line in enumerate(lines, 1):
            for match in re.finditer(method_chain_pattern, line):
                obj = match.group(1)
                method = match.group(2)
                if not _is_keyword(obj) and len(obj) > 1 and not _is_keyword(method) and len(method) > 1:
                    flows.append({
                        "from_var": obj,
                        "to_var": method,
                        "flow_type": "method_chain",
                        "line": i,
                    })

        # Throw pattern
        throw_pattern = r"throw\s+new\s+(\w+)\s*\((.+?)\)\s*;"
        for i, line in enumerate(lines, 1):
            for match in re.finditer(throw_pattern, line):
                exc_type = match.group(1)
                args = match.group(2)
                for var_match in re.finditer(r"\b([a-zA-Z_]\w+)\b", args):
                    var = var_match.group(1)
                    if not _is_keyword(var) and len(var) > 1:
                        flows.append({
                            "from_var": var,
                            "to_var": exc_type,
                            "flow_type": "throw_arg",
                            "line": i,
                        })

        # Return pattern
        return_pattern = r"return\s+([^;]+);"
        for i, line in enumerate(lines, 1):
            for match in re.finditer(return_pattern, line):
                expr = match.group(1).strip()
                for var_match in re.finditer(r"\b([a-zA-Z_]\w+)\b", expr):
                    var = var_match.group(1)
                    if not _is_keyword(var) and len(var) > 1:
                        flows.append({
                            "from_var": var,
                            "to_var": "return_value",
                            "flow_type": "return",
                            "line": i,
                        })

        # Method arg pattern: obj.method(arg1, arg2)
        method_arg_pattern = r"(\w+)\.\w+\s*\(([^)]+)\)"
        for i, line in enumerate(lines, 1):
            for match in re.finditer(method_arg_pattern, line):
                receiver = match.group(1)
                args = match.group(2)
                if _is_keyword(receiver) or len(receiver) <= 1:
                    continue
                for var_match in re.finditer(r"\b([a-zA-Z_]\w+)\b", args):
                    var = var_match.group(1)
                    if not _is_keyword(var) and var != receiver and len(var) > 1:
                        flows.append({
                            "from_var": var,
                            "to_var": receiver,
                            "flow_type": "method_arg",
                            "line": i,
                        })

        logger.debug(f"Extracted {len(flows)} data flows using regex fallback")
        return flows

    def _get_node_text(self, node: Any, source_code: str) -> str:
        """Get text content of an AST node.

        Args:
            node: tree-sitter AST node.
            source_code: Original source code.

        Returns:
            Text content of the node.
        """
        try:
            start_byte = node.start_byte
            end_byte = node.end_byte
            return source_code[start_byte:end_byte]
        except Exception:
            return ""

    def _traverse_and_extract_methods(
        self,
        node: Any,
        source_code: str,
        methods: List[Dict[str, Any]],
    ) -> None:
        """Traverse AST and extract method definitions.

        Args:
            node: Current AST node.
            source_code: Original source code.
            methods: List to accumulate method definitions.
        """
        try:
            if node.type == "method_declaration":
                method_info = self._extract_method_info(node, source_code)
                if method_info:
                    methods.append(method_info)

            for child in node.children:
                self._traverse_and_extract_methods(child, source_code, methods)

        except Exception as e:
            logger.debug(f"Error traversing node: {str(e)}")

    def _extract_method_info(
        self, node: Any, source_code: str
    ) -> Optional[Dict[str, Any]]:
        """Extract metadata from a method declaration node.

        Args:
            node: Method declaration node.
            source_code: Original source code.

        Returns:
            Dictionary with method metadata.
        """
        try:
            method_text = self._get_node_text(node, source_code)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            # Extract method name (simplified)
            name_match = re.search(r"\b(\w+)\s*\(", method_text)
            method_name = name_match.group(1) if name_match else "unknown"

            # Extract parameters (simplified)
            params_match = re.search(r"\((.*?)\)", method_text)
            parameters = params_match.group(1).split(",") if params_match else []
            parameters = [p.strip() for p in parameters if p.strip()]

            # Extract return type (simplified) — skip access/static/final modifiers
            return_type_match = re.search(
                r"(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?(\w+)\s+\w+",
                method_text,
            )
            return_type = return_type_match.group(1) if return_type_match else "void"

            return {
                "name": method_name,
                "start_line": start_line,
                "end_line": end_line,
                "parameters": parameters,
                "body": method_text,
                "return_type": return_type,
                "class_name": None,  # Would need parent class tracking
            }

        except Exception as e:
            logger.debug(f"Error extracting method info: {str(e)}")
            return None

    def _traverse_and_extract_classes(
        self,
        node: Any,
        source_code: str,
        classes: List[Dict[str, Any]],
    ) -> None:
        """Traverse AST and extract class definitions.

        Args:
            node: Current AST node.
            source_code: Original source code.
            classes: List to accumulate class definitions.
        """
        try:
            if node.type == "class_declaration":
                class_info = self._extract_class_info(node, source_code)
                if class_info:
                    classes.append(class_info)

            for child in node.children:
                self._traverse_and_extract_classes(child, source_code, classes)

        except Exception as e:
            logger.debug(f"Error traversing node: {str(e)}")

    def _extract_class_info(
        self, node: Any, source_code: str
    ) -> Optional[Dict[str, Any]]:
        """Extract metadata from a class declaration node.

        Args:
            node: Class declaration node.
            source_code: Original source code.

        Returns:
            Dictionary with class metadata.
        """
        try:
            class_text = self._get_node_text(node, source_code)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            # Extract class name (simplified)
            name_match = re.search(r"class\s+(\w+)", class_text)
            class_name = name_match.group(1) if name_match else "unknown"

            return {
                "name": class_name,
                "start_line": start_line,
                "end_line": end_line,
                "body": class_text,
            }

        except Exception as e:
            logger.debug(f"Error extracting class info: {str(e)}")
            return None

    def _parse_with_regex(self, source_code: str) -> Dict[str, Any]:
        """Fallback regex-based parsing when tree-sitter is unavailable.

        Args:
            source_code: Java source code.

        Returns:
            Parsed code dictionary.
        """
        return {
            "root": None,
            "source": source_code,
            "size": len(source_code),
            "method": "regex",
        }

    def _extract_functions_regex(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract functions using regex (fallback).

        Uses brace counting to capture the full method body.

        Args:
            source_code: Java source code.

        Returns:
            List of extracted functions.
        """
        functions: List[Dict[str, Any]] = []

        # Pattern to match method declarations
        method_pattern = r"(public|private|protected)\s+(static\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)\s*\("

        for match in re.finditer(method_pattern, source_code):
            return_type = match.group(3)
            method_name = match.group(4)

            # Skip class declarations matched as methods
            if return_type == "class" or return_type == "interface":
                continue

            # Find the opening brace
            start_brace = source_code.find("{", match.end())
            if start_brace == -1:
                continue

            # Count braces to find end of method body
            brace_count = 0
            end_pos = start_brace
            for i, char in enumerate(source_code[start_brace:], start=start_brace):
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break

            body = source_code[match.start():end_pos]
            start_line = source_code[:match.start()].count("\n") + 1
            end_line = source_code[:end_pos].count("\n") + 1

            # Extract parameters
            params_match = re.search(r"\((.*?)\)", body)
            parameters = []
            if params_match:
                params_str = params_match.group(1).strip()
                if params_str:
                    parameters = [p.strip() for p in params_str.split(",") if p.strip()]

            functions.append({
                "name": method_name,
                "start_line": start_line,
                "end_line": end_line,
                "parameters": parameters,
                "body": body,
                "return_type": return_type,
                "class_name": None,
            })

        logger.debug(f"Extracted {len(functions)} functions using regex")
        return functions

    def _extract_classes_regex(self, source_code: str) -> List[Dict[str, Any]]:
        """Extract classes using regex (fallback).

        Args:
            source_code: Java source code.

        Returns:
            List of extracted classes.
        """
        classes: List[Dict[str, Any]] = []
        lines = source_code.split("\n")

        # Pattern to match class declarations
        class_pattern = r"(public|private)?\s+class\s+(\w+)"

        for i, line in enumerate(lines):
            match = re.search(class_pattern, line)
            if match:
                class_name = match.group(2)

                classes.append({
                    "name": class_name,
                    "start_line": i + 1,
                    "end_line": len(lines),  # Simplified
                    "body": source_code,
                })

        logger.debug(f"Extracted {len(classes)} classes using regex")
        return classes
