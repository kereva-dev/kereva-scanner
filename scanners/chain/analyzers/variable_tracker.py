"""
Variable Tracker

This module tracks variable assignments and taint propagation.
"""

import ast
import os
from typing import List, Dict, Set

from scanners.chain.taint_analysis import TaintAnalysisVisitor
from core.ast_utils import extract_used_variables


class VariableTracker(TaintAnalysisVisitor):
    """Tracks variable assignments and how taint propagates."""
    
    def __init__(self, untrusted_vars: List[str]):
        super().__init__(untrusted_vars)
        # Track all variable assignments
        self.var_assignments = {}
        # Track variables that are outputs from LLM calls
        self.llm_output_vars = set()
        
    def visit_Assign(self, node):
        """Track variable assignments and taint propagation."""
        # Check if the right side has tainted variables
        tainted = self._is_expression_tainted(node.value)
        taint_sources = self._get_taint_source(node.value) if tainted else []
        
        # Special case for sys.argv assignment (always tainted)
        is_sys_argv = False
        if isinstance(node.value, ast.Subscript):
            # Check for sys.argv[1] pattern
            if (isinstance(node.value.value, ast.Attribute) and 
                isinstance(node.value.value.value, ast.Name) and
                node.value.value.value.id == 'sys' and 
                node.value.value.attr == 'argv'):
                tainted = True
                taint_sources = ['sys.argv']
                is_sys_argv = True
                
        # Special case for input() function (always tainted)
        is_input_call = False
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'input':
            tainted = True
            taint_sources = ['input']
            is_input_call = True
                
        # Special handling for calls in assignments (directly check for LLM API calls)
        is_llm_call = False
        if isinstance(node.value, ast.Call):
            is_llm_call = self._is_llm_api_call(node.value)
        elif isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Call):
            is_llm_call = self._is_llm_api_call(node.value.value)
        else:
            is_llm_call = self._contains_llm_call(node.value)

        # Get the target variable names
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)

        # Record the assignment
        for target in targets:
            self.var_assignments[target] = {
                'node': node.value,
                'tainted': tainted,
                'line': node.lineno,
                'sources': taint_sources,
                'is_llm_output': is_llm_call
            }

            # Update tainted variables
            if tainted or is_llm_call:
                self.tainted_vars.add(target)
                
                if is_llm_call:
                    self.llm_output_vars.add(target)
                    # Mark this variable as LLM-related
                    self.llm_nodes.add(target)

                # Add to flow graph
                self.flow_graph.add_node(target,
                                       type='variable',
                                       tainted=True,
                                       llm_output=is_llm_call,
                                       line=node.lineno)

                for source in taint_sources:
                    if source in self.flow_graph:
                        self.flow_graph.add_edge(source, target, type='taint_flow')
                
                # If this is an LLM call, add a special node for it
                if is_llm_call:
                    llm_node = f"llm_call_{node.lineno}"
                    self.flow_graph.add_node(llm_node, type='llm_call', line=node.lineno)
                    self.llm_nodes.add(llm_node)  # Mark as LLM-related
                    
                    # Connect inputs to the LLM call
                    for source in taint_sources:
                        if source in self.flow_graph:
                            self.flow_graph.add_edge(source, llm_node, type='llm_input')
                    
                    # Connect LLM call to the output variable
                    self.flow_graph.add_edge(llm_node, target, type='llm_output')
            
            elif target in self.tainted_vars:
                self.tainted_vars.remove(target)
                if target in self.llm_output_vars:
                    self.llm_output_vars.remove(target)
                    
        # Continue walking the tree        
        self.generic_visit(node)
        
    def _contains_llm_call(self, node):
        """Check if an expression contains an LLM call anywhere in it."""
        if isinstance(node, ast.Call):
            if self._is_llm_api_call(node):
                return True
            
            # Check if any arguments contain LLM calls
            for arg in node.args:
                if self._contains_llm_call(arg):
                    return True
            
            if hasattr(node, 'keywords'):
                for kw in node.keywords:
                    if self._contains_llm_call(kw.value):
                        return True
        
        # Recursively check all child nodes
        for child in ast.iter_child_nodes(node):
            if self._contains_llm_call(child):
                return True
                
        return False