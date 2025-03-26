"""
Sanitization Detector

This module detects sanitization patterns in the code.
"""

import ast
from typing import List, Dict, Set

from scanners.chain.taint_analysis import TaintAnalysisVisitor
from core.ast_utils import extract_used_variables, get_attribute_chain


class SanitizationDetector(TaintAnalysisVisitor):
    """Analyzes code to detect sanitization of untrusted inputs."""
    
    def __init__(self, untrusted_vars: List[str]):
        super().__init__(untrusted_vars)
        # Track sanitization points
        self.sanitization_points = []
        
    def visit_If(self, node):
        """Handle if statements with sanitization checks."""
        self.generic_visit(node)
        
        # Handle membership checks (in operator)
        if isinstance(node.test, ast.Compare):
            for i, op in enumerate(node.test.ops):
                # Case 1: Detect membership checks (in operator)
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
                        
                        # Mark variables as sanitized in both if body and else body
                        self._mark_sanitized_variables(node, sanitization_id)
                        
                        self.sanitization_points.append({
                            'node': node,
                            'check_type': 'if_membership',
                            'line': node.lineno,
                            'graph_id': sanitization_id,
                            'description': 'If statement with membership check breaks taint flow'
                        })
                        
                # Case 2: Detect not in operator (opposite membership check)
                elif isinstance(op, ast.NotIn):
                    left = node.test.left if i == 0 else node.test.comparators[i-1]
                    right = node.test.comparators[i]
                    
                    # If left is tainted and right is untainted
                    if self._is_expression_tainted(left) and not self._is_expression_tainted(right):
                        sanitization_id = f"sanitize_if_notin_{node.lineno}"
                        self.flow_graph.add_node(sanitization_id,
                                             type='sanitization',
                                             check_type='if_not_in',
                                             line=node.lineno)
                        
                        # Connect tainted sources to sanitization point
                        for source in self._get_taint_source(left):
                            if source in self.flow_graph:
                                self.flow_graph.add_edge(source, sanitization_id, type='sanitized')
                                
                        # Mark variables as sanitized - only in else body for not in
                        self._mark_sanitized_variables(node, sanitization_id, in_body=False, in_else=True)
                        
                        self.sanitization_points.append({
                            'node': node,
                            'check_type': 'if_not_in',
                            'line': node.lineno,
                            'graph_id': sanitization_id,
                            'description': 'If statement with not-in check breaks taint flow'
                        })
        
        # Case 3: Detect re.match or similar regex validation
        # Check for regex pattern matching like re.match(pattern, user_input)
        if isinstance(node.test, ast.Call):
            func = node.test.func
            if isinstance(func, ast.Attribute) and func.attr == 'match':
                if isinstance(func.value, ast.Name) and func.value.id == 're':
                    # This is a re.match call - check if args are tainted
                    if len(node.test.args) >= 2 and self._is_expression_tainted(node.test.args[1]):
                        sanitization_id = f"sanitize_if_regex_{node.lineno}"
                        self.flow_graph.add_node(sanitization_id,
                                             type='sanitization',
                                             check_type='if_regex',
                                             line=node.lineno)
                        
                        # Connect the tainted value to the sanitization point
                        tainted_arg = node.test.args[1]
                        for source in self._get_taint_source(tainted_arg):
                            if source in self.flow_graph:
                                self.flow_graph.add_edge(source, sanitization_id, type='sanitized')
                        
                        # Mark variables as sanitized in if body (validated regex matches)
                        self._mark_sanitized_variables(node, sanitization_id)
                        
                        self.sanitization_points.append({
                            'node': node,
                            'check_type': 'if_regex',
                            'line': node.lineno,
                            'graph_id': sanitization_id,
                            'description': 'If statement with regex validation breaks taint flow'
                        })
                        
        # Case 4: Detect length checks (if len(x) < N)
        if isinstance(node.test, ast.Compare):
            for i, op in enumerate(node.test.ops):
                # Look for comparison operators
                if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                    # Check if left side is a len() call
                    left = node.test.left if i == 0 else node.test.comparators[i-1]
                    
                    if isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == 'len':
                        # This is a len() call
                        if len(left.args) == 1 and self._is_expression_tainted(left.args[0]):
                            sanitization_id = f"sanitize_if_length_{node.lineno}"
                            self.flow_graph.add_node(sanitization_id,
                                                 type='sanitization',
                                                 check_type='if_length',
                                                 line=node.lineno)
                            
                            # Connect the tainted value to the sanitization point
                            tainted_arg = left.args[0]
                            for source in self._get_taint_source(tainted_arg):
                                if source in self.flow_graph:
                                    self.flow_graph.add_edge(source, sanitization_id, type='sanitized')
                            
                            # Mark variables as sanitized
                            self._mark_sanitized_variables(node, sanitization_id)
                            
                            self.sanitization_points.append({
                                'node': node,
                                'check_type': 'if_length',
                                'line': node.lineno,
                                'graph_id': sanitization_id,
                                'description': 'If statement with length check breaks taint flow'
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
                
    def visit_Call(self, node):
        """Check for sanitization function calls."""
        self.generic_visit(node)
        
        # Check if this is a sanitization function call
        if self._is_sanitization_function(node):
            sanitization_id = f"sanitize_func_{node.lineno}"
            self.flow_graph.add_node(sanitization_id,
                                 type='sanitization',
                                 check_type='function_call',
                                 line=node.lineno)
            
            # If there are arguments, connect the first one as the input being sanitized
            if node.args and isinstance(node.args[0], ast.Name):
                input_var = node.args[0].id
                if input_var in self.tainted_vars:
                    self.sanitized_vars.add(input_var)
                    self.flow_graph.add_edge(input_var, sanitization_id, type='sanitized')
                    
                    # Look for the output variable (if this is in an assignment)
                    parent = getattr(node, 'parent', None)
                    if parent and isinstance(parent, ast.Assign) and len(parent.targets) == 1:
                        if isinstance(parent.targets[0], ast.Name):
                            output_var = parent.targets[0].id
                            self.sanitized_vars.add(output_var)
                            
                            # Connect sanitization to output
                            self.flow_graph.add_edge(sanitization_id, output_var, type='sanitized_output')
                            
                            # Update flow graph
                            if output_var in self.flow_graph.nodes:
                                self.flow_graph.nodes[output_var]['sanitized'] = True
                    
                    self.sanitization_points.append({
                        'node': node,
                        'check_type': 'sanitization_function',
                        'line': node.lineno,
                        'graph_id': sanitization_id,
                        'description': 'Sanitization function call breaks taint flow'
                    })
                    
    def _mark_sanitized_variables(self, node, sanitization_id, in_body=True, in_else=False):
        """Mark variables in conditional blocks as sanitized and connect to the flow graph."""
        marked_vars = set()
        
        # Process the 'if' body if requested
        if in_body:
            # First, mark function-level variables if this is in a function
            containing_func = self._find_containing_function(node)
            if containing_func:
                # Mark the function return and all LLM API calls in the function as sanitized
                # This handles return statements inside the if block implicitly
                self.sanitized_vars.add(containing_func.name)
                marked_vars.add(containing_func.name)
                
                # Connect sanitization to the function node in the graph
                if containing_func.name in self.flow_graph:
                    self.flow_graph.add_edge(sanitization_id, containing_func.name, type='sanitized_flow')
                else:
                    self.flow_graph.add_node(containing_func.name, type='function', sanitized=True)
                    self.flow_graph.add_edge(sanitization_id, containing_func.name, type='sanitized_flow')
                    
                # Find all assignments in the function
                for child in ast.walk(containing_func):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                var_name = target.id
                                self.sanitized_vars.add(var_name)
                                marked_vars.add(var_name)
                                
                                # Add to graph if not already there
                                if var_name in self.flow_graph:
                                    self.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
                                else:
                                    self.flow_graph.add_node(var_name, type='variable', sanitized=True)
                                    self.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
            
            # Look for variables assigned inside the if block
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            self.sanitized_vars.add(var_name)
                            marked_vars.add(var_name)
                            
                            # Connect sanitization to the variable
                            if var_name in self.flow_graph:
                                self.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
                            else:
                                # Add the node if it doesn't exist
                                self.flow_graph.add_node(var_name, type='variable', sanitized=True)
                                self.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
        
        # Process the 'else' body if requested and exists
        if in_else and hasattr(node, 'orelse') and node.orelse:
            for child in ast.walk(ast.Module(body=node.orelse, type_ignores=[])):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            self.sanitized_vars.add(var_name)
                            marked_vars.add(var_name)
                            
                            # Connect sanitization to the variable
                            if var_name in self.flow_graph:
                                self.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
                            else:
                                # Add the node if it doesn't exist
                                self.flow_graph.add_node(var_name, type='variable', sanitized=True)
                                self.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
        
        # For debugging
        if self.debug and marked_vars:
            print(f"Marked variables as sanitized: {marked_vars}")
            
    def _is_sanitization_function(self, node):
        """Check if a node is a sanitization function call."""
        from core.config import SANITIZATION_FUNCTION_PATTERNS, OUTPUT_SANITIZATION_FUNCTIONS
        
        # Combine all sanitization function patterns
        all_patterns = SANITIZATION_FUNCTION_PATTERNS + OUTPUT_SANITIZATION_FUNCTIONS
        
        if isinstance(node.func, ast.Name):
            return any(pattern in node.func.id.lower() for pattern in all_patterns)
        
        elif isinstance(node.func, ast.Attribute):
            attr_chain = get_attribute_chain(node.func) 
            if attr_chain:
                full_name = '.'.join(attr_chain)
                return any(pattern in full_name.lower() for pattern in all_patterns)
        
        # Also check for sanitize method name in function definition names
        if isinstance(node.func, ast.Name):
            return ('sanitize' in node.func.id.lower() or 
                   'validate' in node.func.id.lower() or
                   'clean' in node.func.id.lower() or
                   'escape' in node.func.id.lower() or
                   'filter' in node.func.id.lower() or
                   'check' in node.func.id.lower())
                
        return False