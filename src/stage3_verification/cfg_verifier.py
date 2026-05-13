"""Control Flow Graph-based verification with proper CFG building."""

import re
from typing import Dict, List, Optional, Set, Tuple
import networkx as nx

from src.core.models import TaintChain, VerificationStatus
from src.utils.logger import get_logger

logger = get_logger()


class BasicBlock:
    """Represents a basic block in the CFG.

    A basic block is a sequence of statements with:
    - Single entry point
    - Single exit point
    - No branches except at the end
    """

    def __init__(self, block_id: int, statements: List[str]) -> None:
        """Initialize basic block.

        Args:
            block_id: Unique identifier for this block.
            statements: List of code statements in this block.
        """
        self.block_id = block_id
        self.statements = statements
        self.variables: Set[str] = set()
        self.definitions: Set[str] = set()  # Variables defined in this block
        self.uses: Set[str] = set()  # Variables used in this block

        self._extract_variables()

    def _extract_variables(self) -> None:
        """Extract variables defined and used in this block."""
        for stmt in self.statements:
            # Find variable definitions (assignments)
            assign_match = re.search(r'\b([a-zA-Z_]\w*)\s*=', stmt)
            if assign_match:
                var_name = assign_match.group(1)
                self.definitions.add(var_name)
                self.variables.add(var_name)

            # Extract method/constructor parameter names as definitions
            param_match = re.search(r'\(([^)]+)\)', stmt)
            if param_match and re.search(r'(public|private|protected|void|static)', stmt):
                for param in param_match.group(1).split(','):
                    parts = param.strip().split()
                    if len(parts) >= 2:
                        var_name = parts[-1]
                        self.definitions.add(var_name)
                        self.variables.add(var_name)

            # Find variable uses
            var_pattern = r'\b([a-zA-Z_]\w+)\b'
            for match in re.finditer(var_pattern, stmt):
                var_name = match.group(1)
                # Skip keywords
                if var_name not in {'if', 'else', 'while', 'for', 'return', 'new', 'int', 'String', 'boolean', 'void'}:
                    self.uses.add(var_name)
                    self.variables.add(var_name)

    def __repr__(self) -> str:
        return f"Block({self.block_id}, {len(self.statements)} stmts)"


class CFGVerifier:
    """Control Flow Graph-based verification.

    Builds proper CFG from code and performs reachability checking
    considering control flow structures (if/else, loops).
    """

    def __init__(self, max_loop_iterations: int = 10) -> None:
        """Initialize CFG verifier.

        Args:
            max_loop_iterations: Maximum loop iterations to explore (prevents infinite loops).
        """
        self.max_loop_iterations = max_loop_iterations
        self.cfg: Optional[nx.DiGraph] = None
        self.blocks: Dict[int, BasicBlock] = {}
        self.next_block_id = 0

        logger.info(f"Initialized CFGVerifier with max_loop_iterations={max_loop_iterations}")

    def build_cfg(self, source_code: str) -> nx.DiGraph:
        """Build Control Flow Graph from source code.

        Parses code and creates CFG with:
        - Basic blocks
        - Branch edges (if/else)
        - Loop edges (while/for)
        - Sequential edges

        Args:
            source_code: Java source code to analyze.

        Returns:
            NetworkX DiGraph representing the CFG.
        """
        logger.debug("Building CFG from source code")

        self.cfg = nx.DiGraph()
        self.blocks = {}
        self.next_block_id = 0

        # Split into lines and clean
        lines = [line.strip() for line in source_code.split('\n') if line.strip()]

        if not lines:
            logger.warning("Empty source code, returning empty CFG")
            return self.cfg

        # Build CFG by parsing control structures
        entry_block = self._parse_statements(lines, 0, len(lines))

        logger.info(
            f"Built CFG: {self.cfg.number_of_nodes()} blocks, "
            f"{self.cfg.number_of_edges()} edges"
        )

        return self.cfg

    def _parse_statements(
        self,
        lines: List[str],
        start: int,
        end: int,
        parent_block: Optional[int] = None
    ) -> int:
        """Parse statements and build CFG blocks.

        Args:
            lines: List of code lines.
            start: Start index.
            end: End index.
            parent_block: ID of parent block to connect to.

        Returns:
            ID of the last block created.
        """
        current_statements: List[str] = []
        i = start
        current_block = parent_block

        while i < end:
            line = lines[i]

            # Check for control structures
            if line.startswith('if'):
                # Create block for statements before if
                if current_statements:
                    block_id = self._create_block(current_statements)
                    if current_block is not None:
                        self.cfg.add_edge(current_block, block_id, type='sequential')
                    current_block = block_id
                    current_statements = []

                # Parse if statement
                current_block = self._parse_if_statement(lines, i, end, current_block)

                # Find matching else/closing brace
                i = self._find_closing_brace(lines, i) + 1

            elif line.startswith('while') or line.startswith('for'):
                # Create block for statements before loop
                if current_statements:
                    block_id = self._create_block(current_statements)
                    if current_block is not None:
                        self.cfg.add_edge(current_block, block_id, type='sequential')
                    current_block = block_id
                    current_statements = []

                # Parse loop
                current_block = self._parse_loop(lines, i, end, current_block)

                # Find matching closing brace
                i = self._find_closing_brace(lines, i) + 1

            else:
                # Regular statement
                current_statements.append(line)
                i += 1

        # Create final block if we have statements
        if current_statements:
            block_id = self._create_block(current_statements)
            if current_block is not None:
                self.cfg.add_edge(current_block, block_id, type='sequential')
            current_block = block_id

        return current_block if current_block is not None else 0

    def _parse_if_statement(
        self,
        lines: List[str],
        if_idx: int,
        end: int,
        parent_block: Optional[int]
    ) -> int:
        """Parse if/else statement and create CFG branches.

        Args:
            lines: List of code lines.
            if_idx: Index of 'if' statement.
            end: End index.
            parent_block: Parent block to connect from.

        Returns:
            ID of join block after if/else.
        """
        # Create condition block
        condition_line = lines[if_idx]
        condition_block = self._create_block([condition_line])

        if parent_block is not None:
            self.cfg.add_edge(parent_block, condition_block, type='sequential')

        # Find if body (between { and })
        if_start = if_idx + 1
        if_end = self._find_matching_brace(lines, if_idx)

        # Parse if branch
        if_exit = self._parse_statements(lines, if_start, if_end, condition_block)

        # Look for else
        else_exit = condition_block
        if if_end < len(lines) and lines[if_end].strip().startswith('else'):
            else_start = if_end + 1
            else_end = self._find_matching_brace(lines, if_end)
            else_exit = self._parse_statements(lines, else_start, else_end, condition_block)

        # Create join block
        join_block = self._create_block([])

        # Connect branches to join
        if if_exit is not None:
            self.cfg.add_edge(if_exit, join_block, type='branch_merge')
        if else_exit is not None and else_exit != condition_block:
            self.cfg.add_edge(else_exit, join_block, type='branch_merge')
        elif else_exit == condition_block:
            # No else branch, connect condition directly
            self.cfg.add_edge(condition_block, join_block, type='branch')

        return join_block

    def _parse_loop(
        self,
        lines: List[str],
        loop_idx: int,
        end: int,
        parent_block: Optional[int]
    ) -> int:
        """Parse while/for loop and create CFG with back edge.

        Args:
            lines: List of code lines.
            loop_idx: Index of loop statement.
            end: End index.
            parent_block: Parent block to connect from.

        Returns:
            ID of exit block after loop.
        """
        # Create loop header block (condition)
        loop_header = self._create_block([lines[loop_idx]])

        if parent_block is not None:
            self.cfg.add_edge(parent_block, loop_header, type='sequential')

        # Find loop body
        loop_start = loop_idx + 1
        loop_end = self._find_matching_brace(lines, loop_idx)

        # Parse loop body
        loop_body_exit = self._parse_statements(lines, loop_start, loop_end, loop_header)

        # Add back edge from loop body to header
        if loop_body_exit is not None:
            self.cfg.add_edge(loop_body_exit, loop_header, type='loop_back')

        # Create exit block (loop exit)
        exit_block = self._create_block([])
        self.cfg.add_edge(loop_header, exit_block, type='loop_exit')

        return exit_block

    def _create_block(self, statements: List[str]) -> int:
        """Create a new basic block.

        Args:
            statements: List of statements in this block.

        Returns:
            Block ID.
        """
        block_id = self.next_block_id
        self.next_block_id += 1

        block = BasicBlock(block_id, statements)
        self.blocks[block_id] = block

        # Add node to CFG
        self.cfg.add_node(
            block_id,
            statements=statements,
            variables=block.variables,
            definitions=block.definitions,
            uses=block.uses
        )

        return block_id

    def _find_matching_brace(self, lines: List[str], start_idx: int) -> int:
        """Find matching closing brace for a control structure.

        Args:
            lines: List of code lines.
            start_idx: Index of line with opening brace.

        Returns:
            Index of line with matching closing brace.
        """
        brace_count = 0
        found_open = False

        for i in range(start_idx, len(lines)):
            line = lines[i]
            if '{' in line:
                brace_count += 1
                found_open = True
            if '}' in line:
                brace_count -= 1
                if found_open and brace_count == 0:
                    return i

        return len(lines) - 1

    def _find_closing_brace(self, lines: List[str], start_idx: int) -> int:
        """Find closing brace, same as _find_matching_brace."""
        return self._find_matching_brace(lines, start_idx)

    def check_reachability(
        self,
        source_var: str,
        sink_var: str,
        data_flow_graph: Optional[nx.DiGraph] = None
    ) -> bool:
        """Check if sink is reachable from source considering control flow.

        Uses CFG to verify that there exists a control flow path from the
        block defining source to the block using sink.

        Args:
            source_var: Source variable name.
            sink_var: Sink variable name.
            data_flow_graph: Optional data flow graph for additional checking.

        Returns:
            True if sink is reachable from source, False otherwise.
        """
        if self.cfg is None:
            logger.warning("CFG not built, cannot check reachability")
            return False

        # Find blocks containing source and sink
        source_blocks = self._find_blocks_with_variable(source_var, 'definition')
        sink_blocks = self._find_blocks_with_variable(sink_var, 'use')

        if not source_blocks:
            # Method parameters are used but not explicitly defined via assignment
            source_blocks = self._find_blocks_with_variable(source_var, 'use')

        if not source_blocks:
            logger.debug(f"Source variable '{source_var}' not defined in any block")
            return False

        if not sink_blocks:
            logger.debug(f"Sink variable '{sink_var}' not used in any block")
            return False

        # Check if any source block can reach any sink block
        for src_block in source_blocks:
            for sink_block in sink_blocks:
                if self._is_reachable_with_loops(src_block, sink_block):
                    logger.debug(
                        f"CFG reachability: {source_var} (block {src_block}) -> "
                        f"{sink_var} (block {sink_block}): TRUE"
                    )
                    return True

        logger.debug(f"CFG reachability: {source_var} -> {sink_var}: FALSE")
        return False

    def _find_blocks_with_variable(
        self,
        var_name: str,
        access_type: str = 'any'
    ) -> List[int]:
        """Find all blocks that define or use a variable.

        Args:
            var_name: Variable name to search for.
            access_type: 'definition', 'use', or 'any'.

        Returns:
            List of block IDs.
        """
        blocks = []

        for block_id, block in self.blocks.items():
            if access_type == 'definition' and var_name in block.definitions:
                blocks.append(block_id)
            elif access_type == 'use' and var_name in block.uses:
                blocks.append(block_id)
            elif access_type == 'any' and var_name in block.variables:
                blocks.append(block_id)

        return blocks

    def _is_reachable_with_loops(
        self,
        source_block: int,
        sink_block: int
    ) -> bool:
        """Check reachability considering loops with iteration limit.

        Uses bounded BFS to explore paths while limiting loop iterations.

        Args:
            source_block: Source block ID.
            sink_block: Sink block ID.

        Returns:
            True if sink is reachable from source within loop limit.
        """
        if source_block == sink_block:
            return True

        if source_block not in self.cfg or sink_block not in self.cfg:
            return False

        # Use BFS with loop iteration tracking
        visited = set()
        queue = [(source_block, {})]  # (block_id, loop_iterations)

        while queue:
            current, loop_iters = queue.pop(0)

            if current == sink_block:
                return True

            if current in visited:
                continue

            visited.add(current)

            # Explore successors
            for successor in self.cfg.successors(current):
                edge_type = self.cfg[current][successor].get('type', 'sequential')

                # Handle loop back edges
                if edge_type == 'loop_back':
                    # Count loop iterations
                    loop_key = (current, successor)
                    iterations = loop_iters.get(loop_key, 0)

                    if iterations < self.max_loop_iterations:
                        new_loop_iters = loop_iters.copy()
                        new_loop_iters[loop_key] = iterations + 1
                        queue.append((successor, new_loop_iters))
                else:
                    # Regular edge
                    queue.append((successor, loop_iters.copy()))

        return False

    def verify_chain(self, chain: TaintChain, source_code: str) -> VerificationStatus:
        """Verify a taint chain using CFG analysis.

        Args:
            chain: TaintChain to verify.
            source_code: Source code to build CFG from.

        Returns:
            VerificationStatus indicating verification result.
        """
        logger.debug(
            f"Verifying chain with CFG: {chain.source.variable_name} -> "
            f"{chain.sink.variable_name}"
        )

        # Build CFG if not already built
        if self.cfg is None:
            self.build_cfg(source_code)

        # Check reachability
        is_reachable = self.check_reachability(
            chain.source.variable_name,
            chain.sink.variable_name
        )

        if is_reachable:
            logger.info(
                f"✓ CFG verification: {chain.source.variable_name} -> "
                f"{chain.sink.variable_name} VERIFIED"
            )
            return VerificationStatus.VERIFIED
        else:
            logger.info(
                f"✗ CFG verification: {chain.source.variable_name} -> "
                f"{chain.sink.variable_name} FALSE"
            )
            return VerificationStatus.FALSE

    def get_cfg_info(self) -> Dict:
        """Get information about the CFG.

        Returns:
            Dictionary with CFG statistics.
        """
        if self.cfg is None:
            return {
                "built": False,
                "blocks": 0,
                "edges": 0,
            }

        # Count edge types
        edge_types = {}
        for _, _, data in self.cfg.edges(data=True):
            edge_type = data.get('type', 'unknown')
            edge_types[edge_type] = edge_types.get(edge_type, 0) + 1

        return {
            "built": True,
            "blocks": self.cfg.number_of_nodes(),
            "edges": self.cfg.number_of_edges(),
            "edge_types": edge_types,
            "variables": sum(len(block.variables) for block in self.blocks.values()),
        }
