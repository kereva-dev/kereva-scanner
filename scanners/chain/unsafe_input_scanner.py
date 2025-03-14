import ast
import os
import networkx as nx
from typing import List, Dict, Set, Any, Optional, Tuple

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.ast_utils import (
    get_function_name, extract_string_value, extract_used_variables, 
    is_call_matching, get_attribute_chain
)
from core.config import LLM_API_PATTERNS, UNTRUSTED_INPUT_PATTERNS
from rules.chain.unsafe_input_rule import UnsafeInputRule


class UnsafeInputScanner(BaseScanner):
    """Scanner for detecting vulnerable LLM prompt chains with unsanitized inputs."""
    
    def __init__(self, untrusted_vars: Optional[List[str]] = None):
        # Initialize with the appropriate rules
        rules = [
            UnsafeInputRule()
        ]
        super().__init__(rules)
        self.untrusted_vars = untrusted_vars or UNTRUSTED_INPUT_PATTERNS
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Perform full taint analysis on the AST to detect LLM chain vulnerabilities."""
        context = context or {}
        self.reset()  # Clear any previous issues
        
        debug = os.environ.get('DEBUG') == "1"
        
        # Allow context to override default untrusted vars
        if "untrusted_vars" in context:
            self.untrusted_vars = context["untrusted_vars"]
        
        # Add untrusted vars to the context so the rule has access to them
        context["untrusted_params"] = self.untrusted_vars
        
        if debug:
            print(f"UnsafeInputScanner scanning file: {context.get('file_name', 'unknown')}")
            print(f"Untrusted variables: {self.untrusted_vars}")
            
        # First approach: Apply the UnsafeInputRule directly to the AST
        # This will handle simpler cases but may miss complex taint flows
        self.apply_rules(ast_node, context)
        
        # Second approach: Use full taint analysis for complex flows
        # If no issues were found with the simple approach, or if we want to be thorough
        if not self.issues or context.get("thorough", True):
            analyzer = LLMPromptChainAnalyzer(self.untrusted_vars)
            
            # First pass to identify LLM wrapper functions
            analyzer.visit(ast_node)
            
            # Second pass to analyze data flow with knowledge of wrapper functions
            analyzer.visit(ast_node)
            
            # Get vulnerabilities from the analyzer
            vulnerabilities = analyzer.analyze_vulnerabilities()
            
            # Convert vulnerabilities to Issue objects
            for vuln in vulnerabilities:
                line_number = self._find_line_number(vuln)
                issue = Issue(
                    rule_id="chain-unsanitized-input",
                    message=vuln["description"],
                    location={
                        "file": context.get("file_name", "<unknown>"),
                        "line": line_number,
                        "column": 0
                    },
                    severity="high",
                    fix_suggestion=(
                        "Implement input validation or sanitization before passing "
                        "untrusted input to LLM. Consider using an allow-list approach."
                    ),
                    context={
                        "source": vuln["source"],
                        "sink": vuln["sink"],
                        "path": " -> ".join(vuln["path"]) if "path" in vuln else ""
                    }
                )
                self.register_issue(issue)
                
        if debug:
            print(f"Final count of issues: {len(self.issues)}")
                
        return self.issues
    
    def _find_line_number(self, vulnerability: Dict[str, Any]) -> int:
        """Extract a line number from a vulnerability."""
        # Try to find a line number in the path
        if "path" in vulnerability:
            # First try to find an LLM call node which has the line number in its name
            for node in vulnerability["path"]:
                if isinstance(node, str) and node.startswith("llm_call_"):
                    try:
                        return int(node.split("_")[-1])
                    except (ValueError, IndexError):
                        pass
                
        return 1  # Return line 1 as a default


class LLMPromptChainAnalyzer(ast.NodeVisitor):
    """Analyzes code for untrusted input flowing through LLM chains."""
    
    def __init__(self, untrusted_vars: List[str]):
        # Variables marked as untrusted
        self.untrusted_vars = set(untrusted_vars)
        # Currently tainted variables
        self.tainted_vars = set(untrusted_vars)
        # Track which variables are outputs from LLM calls
        self.llm_output_vars = set()
        # Track variable assignments
        self.var_assignments = {}
        # Track sanitization points
        self.sanitization_points = []
        # Track sanitized variables
        self.sanitized_vars = set()
        # Track vulnerabilities
        self.vulnerabilities = []
        # Data flow graph
        self.flow_graph = nx.DiGraph()
        # Known LLM function wrappers
        self.llm_wrappers = set()
        # Track which nodes in the graph are LLM-related
        self.llm_nodes = set()
        # Use the shared LLM API patterns
        self.llm_api_patterns = LLM_API_PATTERNS

        # Add untrusted sources to the graph
        for var in untrusted_vars:
            self.flow_graph.add_node(var, type='source', tainted=True)
            
        # Add sys.argv as a special untrusted source
        self.flow_graph.add_node('sys.argv', type='source', tainted=True)

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

    def visit_If(self, node):
        """Handle if statements with sanitization checks."""
        self.generic_visit(node)
        
        # Check if the test condition is a membership check (in operator)
        if isinstance(node.test, ast.Compare):
            for i, op in enumerate(node.test.ops):
                if isinstance(op, ast.In):
                    left = node.test.left if i == 0 else node.test.comparators[i-1]
                    right = node.test.comparators[i]
                    
                    # If left is tainted (the value being checked) and right is untainted (the set)
                    if self._is_expression_tainted(left) and not self._is_expression_tainted(right):
                        # This is a sanitization check
                        sanitization_id = f"sanitize_if_{node.lineno}"
                        self.flow_graph.add_node(sanitization_id,
                                             type='sanitization',
                                             check_type='if_membership',
                                             line=node.lineno)
                        
                        # Connect the tainted value to the sanitization point
                        for source in self._get_taint_source(left):
                            if source in self.flow_graph:
                                self.flow_graph.add_edge(source, sanitization_id, type='sanitized')
                        
                        # Find all assignments in the if body
                        for child in node.body:
                            if isinstance(child, ast.Assign):
                                for target in child.targets:
                                    if isinstance(target, ast.Name):
                                        # Mark this variable as sanitized
                                        self.sanitized_vars.add(target.id)
                                        
                                        # Connect sanitization to the variable
                                        if target.id in self.flow_graph:
                                            self.flow_graph.add_edge(sanitization_id, target.id, type='sanitized_flow')
                        
                        self.sanitization_points.append({
                            'node': node,
                            'check_type': 'if_membership',
                            'line': node.lineno,
                            'graph_id': sanitization_id,
                            'description': 'If statement with membership check breaks taint flow'
                        })

    def visit_Compare(self, node):
        """Handle comparison operations, including set membership checks."""
        self.generic_visit(node)

        # Check for 'in' operator (set membership)
        for i, op in enumerate(node.ops):
            if isinstance(op, ast.In):
                left = node.left if i == 0 else node.comparators[i-1]
                right = node.comparators[i]

                # If left is tainted (the value being checked) and right is untainted (the set)
                if self._is_expression_tainted(left) and not self._is_expression_tainted(right):
                    sanitization_id = f"sanitize_membership_{node.lineno}"
                    self.flow_graph.add_node(sanitization_id,
                                         type='sanitization',
                                         check_type='membership',
                                         line=node.lineno)

                    # Connect the tainted value to the sanitization point
                    for source in self._get_taint_source(left):
                        if source in self.flow_graph:
                            self.flow_graph.add_edge(source, sanitization_id, type='sanitized')

                    self.sanitization_points.append({
                        'node': node,
                        'check_type': 'membership',
                        'line': node.lineno,
                        'graph_id': sanitization_id,
                        'description': 'Set membership check breaks taint flow'
                    })

                    return sanitization_id

    def visit_Subscript(self, node):
        """Handle dictionary/list lookups which act as sanitization."""
        self.generic_visit(node)
        
        # Check if this is a container lookup that might sanitize
        if isinstance(node.value, ast.Name):
            container_name = node.value.id
            
            # If the key/index is tainted but the container is not
            if self._is_expression_tainted(node.slice) and not self._is_expression_tainted(node.value):
                sanitization_id = f"sanitize_{node.lineno}"
                self.flow_graph.add_node(sanitization_id,
                                     type='sanitization',
                                     container=container_name,
                                     line=node.lineno)

                # Connect the tainted key to the sanitization point
                for source in self._get_taint_source(node.slice):
                    if source in self.flow_graph:
                        self.flow_graph.add_edge(source, sanitization_id, type='sanitized')

                self.sanitization_points.append({
                    'node': node,
                    'container': container_name,
                    'line': node.lineno,
                    'graph_id': sanitization_id,
                    'description': f"Dictionary/list lookup in '{container_name}' breaks taint flow"
                })

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

    def _is_expression_tainted(self, node):
        """Check if an expression contains tainted variables."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.Call):
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

    def _path_contains_llm(self, path):
        """Check if a path contains at least one LLM-related node."""
        return any(node in self.llm_nodes for node in path)

    def analyze_vulnerabilities(self):
        """Analyze the code for straight paths from untrusted inputs through LLMs to outputs."""
        # Track unique vulnerabilities to avoid duplicates
        unique_vulnerabilities = set()
        
        # Identify LLM API calls in the code (potential sinks)
        llm_call_nodes = [node for node in self.flow_graph.nodes() if isinstance(node, str) and node.startswith('llm_call_')]
        
        # Find all inputs to LLM API calls
        for llm_node in llm_call_nodes:
            # Get predecessors (inputs to the LLM call)
            llm_inputs = list(self.flow_graph.predecessors(llm_node))
            
            # Check each input for taint
            for input_var in llm_inputs:
                if isinstance(input_var, str) and input_var in self.tainted_vars:
                    # This is a tainted input to an LLM - trace back to the source
                    for source in self.untrusted_vars:
                        if source in self.flow_graph:
                            try:
                                # Find all paths from untrusted source to this input
                                source_paths = list(nx.all_simple_paths(self.flow_graph, source, input_var))
                                if source_paths:
                                    # Create a vulnerability for each unique source->LLM path
                                    vuln_id = f"{source}_{llm_node}"
                                    if vuln_id not in unique_vulnerabilities:
                                        unique_vulnerabilities.add(vuln_id)
                                        self.vulnerabilities.append({
                                            'type': 'untrusted_to_llm',
                                            'source': source,
                                            'sink': llm_node,
                                            'path': source_paths[0],  # Include one example path
                                            'description': f"Untrusted input '{source}' flows to LLM API call without proper sanitization"
                                        })
                            except nx.NetworkXNoPath:
                                # No path exists
                                pass
                                
        # Also check for sys.argv specifically since it's a common untrusted source
        for var, info in self.var_assignments.items():
            # If this variable comes from sys.argv
            if isinstance(info.get('node'), ast.Subscript):
                node = info.get('node')
                if (isinstance(node.value, ast.Attribute) and 
                    isinstance(node.value.value, ast.Name) and
                    node.value.value.id == 'sys' and 
                    node.value.attr == 'argv'):
                    # This variable comes from sys.argv - check if it flows to an LLM
                    for llm_node in llm_call_nodes:
                        # Find paths from this variable to any LLM call
                        if var in self.flow_graph and llm_node in self.flow_graph:
                            try:
                                paths = list(nx.all_simple_paths(self.flow_graph, var, llm_node))
                                if paths:
                                    # Create a vulnerability
                                    vuln_id = f"sys.argv_{var}_{llm_node}"
                                    if vuln_id not in unique_vulnerabilities:
                                        unique_vulnerabilities.add(vuln_id)
                                        self.vulnerabilities.append({
                                            'type': 'system_argv_to_llm',
                                            'source': f"sys.argv via {var}",
                                            'sink': llm_node,
                                            'path': paths[0],
                                            'description': f"Command line argument from sys.argv flows to LLM without proper sanitization"
                                        })
                            except nx.NetworkXNoPath:
                                # No path exists
                                pass
                                
        # Also check standard outputs as in the original code
        output_vars = set()
        for var in self.var_assignments:
            # Consider variables that are used as final outputs or start with 'output'
            if var.startswith('output') or var.startswith('result'):
                output_vars.add(var)

        # For each output, check if there's a path from an untrusted source
        for output in output_vars:
            # Skip if this output is in our sanitized variables list
            if output in self.sanitized_vars:
                continue
                
            for source in self.untrusted_vars:
                if source in self.flow_graph and output in self.flow_graph:
                    try:
                        # Find all simple paths from source to output
                        all_paths = list(nx.all_simple_paths(self.flow_graph, source, output))
                        
                        # Filter to only include paths that contain an LLM node
                        llm_paths = [path for path in all_paths if self._path_contains_llm(path)]
                        
                        # Check if any path is not sanitized
                        for path in llm_paths:
                            # Check if the path contains a sanitization point
                            sanitized = any(
                                isinstance(node, str) and node.startswith('sanitize_') 
                                for node in path
                            )
                            
                            if not sanitized:
                                # Create a unique identifier for this vulnerability
                                vuln_id = f"{source}_{output}"
                                
                                if vuln_id not in unique_vulnerabilities:
                                    unique_vulnerabilities.add(vuln_id)
                                    self.vulnerabilities.append({
                                        'type': 'llm_straight_path',
                                        'source': source,
                                        'sink': output,
                                        'path': path,  # Include one example path
                                        'description': f"Straight path from untrusted input '{source}' through LLM to output '{output}'"
                                    })
                                break  # Only need one example of a vulnerable path
                                
                    except nx.NetworkXNoPath:
                        # No path exists
                        pass

        return self.vulnerabilities