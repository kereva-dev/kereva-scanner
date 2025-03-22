"""
Chain Analyzer

A unified module for analyzing chains of data flow in code.
"""

import ast
import networkx as nx
from typing import List, Dict, Set, Any, Optional, Tuple

from core.config import UNTRUSTED_INPUT_PATTERNS
from scanners.chain.analyzers import (
    LLMFunctionAnalyzer,
    VariableTracker, 
    SanitizationDetector,
    VulnerabilityAnalyzer
)


class ChainAnalyzer:
    """
    A unified analyzer for LLM chains that combines multiple specialized analyzers.
    
    This class coordinates the work of several specialized analyzers to perform
    a comprehensive analysis of code for data flow issues, especially focusing on
    untrusted inputs flowing to LLM API calls.
    """
    
    def __init__(self, untrusted_vars: Optional[List[str]] = None):
        """
        Initialize the chain analyzer with untrusted variable patterns.
        
        Args:
            untrusted_vars: Optional list of variable name patterns to consider untrusted.
                            Defaults to patterns from config.
        """
        self.untrusted_vars = untrusted_vars or UNTRUSTED_INPUT_PATTERNS
        
        # Initialize specialized analyzers
        self.llm_analyzer = None
        self.var_tracker = None
        self.sanitizer = None
        
        # Results
        self.flow_graph = nx.DiGraph()
        self.tainted_vars = set()
        self.sanitized_vars = set()
        self.llm_nodes = set()
        self.vulnerabilities = []
        
    def analyze(self, ast_node):
        """
        Perform a comprehensive analysis of code for chain vulnerabilities.
        
        Args:
            ast_node: The AST node to analyze (typically a Module node)
            
        Returns:
            Self, for method chaining
        """
        # Step 1: First pass to identify LLM wrapper functions
        self.llm_analyzer = LLMFunctionAnalyzer(self.untrusted_vars)
        self.llm_analyzer.visit(ast_node)
        
        # Step 2: Track variable assignments and taint propagation
        self.var_tracker = VariableTracker(self.untrusted_vars)
        # Share what we learned about LLM wrappers
        self.var_tracker.llm_wrappers = self.llm_analyzer.llm_wrappers
        self.var_tracker.llm_api_patterns = self.llm_analyzer.llm_api_patterns
        self.var_tracker.visit(ast_node)
        
        # Step 3: Detect sanitization patterns
        self.sanitizer = SanitizationDetector(self.untrusted_vars)
        # Share the state we've already built up
        self.sanitizer.llm_wrappers = self.llm_analyzer.llm_wrappers
        self.sanitizer.llm_api_patterns = self.llm_analyzer.llm_api_patterns
        self.sanitizer.tainted_vars = self.var_tracker.tainted_vars.copy()
        self.sanitizer.flow_graph = self.var_tracker.flow_graph.copy()
        self.sanitizer.visit(ast_node)
        
        # Step 4: Merge flow graphs for complete analysis
        self.flow_graph = nx.DiGraph()
        self.flow_graph.add_nodes_from(self.llm_analyzer.flow_graph.nodes(data=True))
        self.flow_graph.add_edges_from(self.llm_analyzer.flow_graph.edges(data=True))
        self.flow_graph.add_nodes_from(self.var_tracker.flow_graph.nodes(data=True))
        self.flow_graph.add_edges_from(self.var_tracker.flow_graph.edges(data=True))
        self.flow_graph.add_nodes_from(self.sanitizer.flow_graph.nodes(data=True))
        self.flow_graph.add_edges_from(self.sanitizer.flow_graph.edges(data=True))
        
        # Collect results
        self.tainted_vars = self.var_tracker.tainted_vars
        self.sanitized_vars = self.sanitizer.sanitized_vars
        self.llm_nodes = self.llm_analyzer.llm_nodes.union(self.var_tracker.llm_nodes)
        
        return self
    
    def find_vulnerabilities(self):
        """
        Find vulnerabilities in the analyzed code.
        
        Returns:
            List of vulnerability dictionaries
        """
        # Step 5: Analyze vulnerabilities
        analyzer = VulnerabilityAnalyzer(
            flow_graph=self.flow_graph,
            untrusted_vars=self.untrusted_vars,
            sanitized_vars=self.sanitized_vars,
            llm_nodes=self.llm_nodes
        )
        
        self.vulnerabilities = analyzer.analyze_vulnerabilities()
        return self.vulnerabilities
    
    def get_function_wrappers(self):
        """
        Get the list of detected LLM wrapper functions.
        
        Returns:
            Set of function names that wrap LLM API calls
        """
        if self.llm_analyzer:
            return self.llm_analyzer.llm_wrappers
        return set()
    
    def get_llm_api_calls(self):
        """
        Get the list of detected LLM API calls.
        
        Returns:
            List of AST Call nodes representing LLM API calls
        """
        if self.llm_analyzer:
            return self.llm_analyzer.llm_api_calls
        return []
    
    def get_variable_assignments(self):
        """
        Get the map of variable assignments and their properties.
        
        Returns:
            Dict mapping variable names to their assignment info
        """
        if self.var_tracker:
            return self.var_tracker.var_assignments
        return {}
    
    def get_sanitization_points(self):
        """
        Get the list of detected sanitization points.
        
        Returns:
            List of sanitization point dictionaries
        """
        if self.sanitizer:
            return self.sanitizer.sanitization_points
        return []