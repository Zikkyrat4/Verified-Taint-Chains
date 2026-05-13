"""Type aliases and helper types for taint analysis."""

from typing import Dict, List, Set, Tuple

# Type aliases for graph operations
NodeId = str
EdgeWeight = float
NodeAttributes = Dict[str, any]

# Variables found in code
Variables = Set[str]

# Data flow information
DataFlowEdge = Tuple[str, str]  # (source, target) variable names
DataFlowPath = List[str]  # Ordered list of variable names in path

# Graph representations
GraphDict = Dict[str, List[str]]  # Simple adjacency list: node -> [neighbors]
