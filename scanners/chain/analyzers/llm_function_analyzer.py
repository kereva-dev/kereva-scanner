"""
LLM Function Analyzer

This module detects LLM wrapper functions and API calls in the code.
"""

import ast
from typing import Set, List

from scanners.chain.taint_analysis import TaintAnalysisVisitor
from core.ast_utils import is_call_matching, get_attribute_chain
from core.config import LLM_UNTRUSTED_PARAM_NAMES


class LLMFunctionAnalyzer(TaintAnalysisVisitor):
    """Analyzes code to identify functions that wrap LLM API calls."""
    
    def __init__(self, untrusted_vars: List[str]):
        super().__init__(untrusted_vars)
        # Track all detected LLM API calls
        self.llm_api_calls = []
        
    def visit_FunctionDef(self, node):
        """Identify functions that wrap LLM calls"""
        self.generic_visit(node)
        
        # Check if this function contains LLM API calls
        contains_llm_call = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self._is_llm_api_call(child):
                contains_llm_call = True
                break
        
        if contains_llm_call:
            self.llm_wrappers.add(node.name)
            # Add to our LLM API patterns
            self.llm_api_patterns.append({
                'type': 'function', 
                'names': [node.name]
            })
            
            if self.debug:
                print(f"Detected LLM wrapper function: {node.name}")
    
    def visit_Call(self, node):
        """Record all LLM API calls."""
        self.generic_visit(node)
        
        if self._is_llm_api_call(node):
            self.llm_api_calls.append(node)
            
            # Add to flow graph as an LLM call node
            llm_node_id = f"llm_call_{node.lineno}"
            self.flow_graph.add_node(llm_node_id, 
                                   type='sink', 
                                   sink_type='llm', 
                                   line=node.lineno)
            self.llm_nodes.add(llm_node_id)
            
            # Process the inputs to this LLM call
            self._process_llm_inputs(node, llm_node_id)
    
    def _process_llm_inputs(self, node, llm_node_id):
        """Process the inputs to an LLM API call and add to flow graph."""
        # Check positional arguments
        for arg in node.args:
            if self._is_expression_tainted(arg):
                for source in self._get_taint_source(arg):
                    if source in self.flow_graph:
                        self.flow_graph.add_edge(source, llm_node_id, type='llm_input')
        
        # Check keyword arguments
        for kw in node.keywords:
            if kw.arg in LLM_UNTRUSTED_PARAM_NAMES:
                if self._is_expression_tainted(kw.value):
                    for source in self._get_taint_source(kw.value):
                        if source in self.flow_graph:
                            self.flow_graph.add_edge(source, llm_node_id, type='llm_input')