"""
Taint Analysis Module

Contains taint analysis functionality for tracking the flow of untrusted data through code.
"""

import ast
import os
import networkx as nx
from typing import List, Dict, Set, Any, Optional, Tuple

from core.ast_utils import (
    get_function_name, extract_string_value, extract_used_variables, 
    is_call_matching, get_attribute_chain
)
from core.config import (
    LLM_API_PATTERNS, UNTRUSTED_INPUT_PATTERNS, 
    SANITIZATION_FUNCTION_PATTERNS
)


class TaintAnalysisVisitor(ast.NodeVisitor):
    """Base visitor for taint analysis that tracks flow of untrusted inputs."""
    
    def __init__(self, untrusted_vars: List[str]):
        # Variables marked as untrusted
        self.untrusted_vars = set(untrusted_vars)
        # Currently tainted variables
        self.tainted_vars = set(untrusted_vars)
        # Variables that have been sanitized
        self.sanitized_vars = set()
        # Data flow graph
        self.flow_graph = nx.DiGraph()
        # Known LLM function wrappers
        self.llm_wrappers = set()
        # Track which nodes in the graph are LLM-related
        self.llm_nodes = set()
        # Use the shared LLM API patterns
        self.llm_api_patterns = LLM_API_PATTERNS.copy()
        # Parent node tracking
        self.parent_map = {}
        # Debug mode
        self.debug = os.environ.get('DEBUG') == "1"

        # Add untrusted sources to the graph and ensure they're marked as tainted
        for var in untrusted_vars:
            self.flow_graph.add_node(var, type='source', tainted=True)
            self.tainted_vars.add(var)
            
        # Add sys.argv as a special untrusted source
        self.flow_graph.add_node('sys.argv', type='source', tainted=True)
        
    def generic_visit(self, node):
        """Override to add parent tracking."""
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        item.parent = node
                        self.parent_map[item] = node
                        self.visit(item)
            elif isinstance(value, ast.AST):
                value.parent = node
                self.parent_map[value] = node
                self.visit(value)
                
    def visit(self, node):
        """Add parent reference to node and call appropriate visit method."""
        # Ensure node parent tracking is available even for nodes from first visit
        if not hasattr(node, 'parent'):
            node.parent = getattr(node, 'parent', None)
        
        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def _is_expression_tainted(self, node):
        """Check if an expression contains tainted variables."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.Call):
            # Special case: input() is always tainted
            if isinstance(node.func, ast.Name) and node.func.id == 'input':
                return True
                
            # Check if any arguments are tainted
            if hasattr(node, 'args'):
                if any(self._is_expression_tainted(arg) for arg in node.args):
                    return True
            if hasattr(node, 'keywords'):
                if any(self._is_expression_tainted(kw.value) for kw in node.keywords):
                    return True
        elif isinstance(node, ast.BinOp):
            # Check binary operations (like string concatenation)
            return self._is_expression_tainted(node.left) or self._is_expression_tainted(node.right)
        elif isinstance(node, ast.Subscript):
            # For dictionary/list access, check both the container and index
            if isinstance(node.value, ast.Name) and node.value.id == 'sys' and isinstance(node.slice, ast.Constant) and node.slice.value == 'argv':
                # sys.argv is always tainted
                return True
                
            # Check for sys.argv[n] pattern
            if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
                if node.value.value.id == 'sys' and node.value.attr == 'argv':
                    # Any access to sys.argv is tainted
                    return True
                    
            # For dictionary/list access, check both the container and index
            return self._is_expression_tainted(node.value) or self._is_expression_tainted(node.slice)
        elif isinstance(node, ast.FormattedValue):
            # For f-strings
            return self._is_expression_tainted(node.value)
        elif isinstance(node, ast.JoinedStr):
            # For f-strings
            return any(self._is_expression_tainted(value) for value in node.values)
        elif isinstance(node, ast.Attribute):
            # Check for sys.argv access
            if isinstance(node.value, ast.Name) and node.value.id == 'sys' and node.attr == 'argv':
                return True

        # Recursively check other node types
        for child in ast.iter_child_nodes(node):
            if self._is_expression_tainted(child):
                return True

        return False

    def _get_taint_source(self, node):
        """Get the source of taint in an expression."""
        # Use the shared extract_used_variables utility
        used_vars = extract_used_variables(node)
        
        # Filter to only include variables that are tainted
        tainted_vars = [var for var in used_vars if var in self.tainted_vars]
        
        return tainted_vars

    def _is_llm_api_call(self, node):
        """Check if a node represents an LLM API call based on configured patterns."""
        if not isinstance(node, ast.Call):
            return False
            
        # Extract the function name
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            attr_chain = get_attribute_chain(node.func)
            func_name = ".".join(attr_chain)
            
        # Check for common LLM API patterns
        if func_name in ["openai.chat.completions.create", "chat.completions.create"]:
            return True
            
        # Use the shared is_call_matching utility
        is_llm_call = is_call_matching(node, self.llm_api_patterns)
        
        # Also check known wrapper functions
        if isinstance(node.func, ast.Name) and node.func.id in self.llm_wrappers:
            return True
            
        return is_llm_call

    def _find_containing_function(self, node):
        """Find the function containing the given node."""
        # Start from parent and go up looking for a FunctionDef node
        parent = getattr(node, 'parent', None)
        while parent is not None:
            if isinstance(parent, ast.FunctionDef):
                return parent
            parent = getattr(parent, 'parent', None)
        return None