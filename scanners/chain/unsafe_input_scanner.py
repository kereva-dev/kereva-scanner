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
            
            # First pass to identify LLM wrapper functions and build parent map
            analyzer.visit(ast_node)
            
            # Second pass to analyze data flow with knowledge of wrapper functions
            analyzer.visit(ast_node)
            
            # Special handling for functions with input validation patterns
            self._process_validated_functions(ast_node, analyzer)
            
            # Get vulnerabilities from the analyzer
            vulnerabilities = analyzer.analyze_vulnerabilities()
            
            # Convert vulnerabilities to Issue objects
            # Get rule ID from the rule instance rather than hardcoding it
            rule_id = self.rules[0].rule_id if self.rules else "chain-unsafe-input"
            
            for vuln in vulnerabilities:
                line_number = self._find_line_number(vuln)
                issue = Issue(
                    rule_id=rule_id,  # Use the rule ID from the rule instance
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
                    },
                    tags=self.rules[0].tags if self.rules else ["security", "sanitization", "prompt-engineering"]
                )
                self.register_issue(issue)
                
        if debug:
            print(f"Final count of issues: {len(self.issues)}")
                
        return self.issues
        
    def _process_validated_functions(self, ast_node, analyzer):
        """
        Special handling for functions that validate input before passing to LLM.
        Identifies common validation patterns like allowlists and regex checks.
        """
        for node in ast.walk(ast_node):
            if isinstance(node, ast.FunctionDef):
                # Check if any function parameter matches untrusted pattern
                has_untrusted_param = False
                param_names = []
                for arg in node.args.args:
                    param_names.append(arg.arg)
                    if arg.arg in self.untrusted_vars:
                        has_untrusted_param = True
                        
                if not has_untrusted_param and not any(p in self.untrusted_vars for p in param_names):
                    continue
                
                # Check for validation patterns in the function
                validation_found = False
                
                # Look for if statements with validation
                for child in ast.walk(node):
                    if isinstance(child, ast.If):
                        # Look for common validation patterns
                        if isinstance(child.test, ast.Compare):
                            for op in child.test.ops:
                                # Check for membership checks (in/not in)
                                if isinstance(op, (ast.In, ast.NotIn)):
                                    validation_found = True
                                    # Mark this function as safe (all variables in it are sanitized)
                                    analyzer.sanitized_vars.add(node.name)
                                    for param in param_names:
                                        analyzer.sanitized_vars.add(param)
                                        
                                    # Also add to flow graph if not present
                                    sanitization_id = f"sanitize_func_{node.lineno}"
                                    analyzer.flow_graph.add_node(sanitization_id, 
                                                              type='sanitization',
                                                              check_type='function_validation',
                                                              line=node.lineno)
                                    
                                    # Connect to all variables in the function
                                    for var in ast.walk(node):
                                        if isinstance(var, ast.Name) and isinstance(var.ctx, ast.Store):
                                            var_name = var.id
                                            analyzer.sanitized_vars.add(var_name)
                                            if var_name in analyzer.flow_graph:
                                                analyzer.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
                                    break
                        
                        # Check for regex validation
                        elif isinstance(child.test, ast.Call):
                            func = child.test.func
                            if isinstance(func, ast.Attribute) and func.attr == 'match':
                                if isinstance(func.value, ast.Name) and func.value.id == 're':
                                    validation_found = True
                                    # Mark this function as safe
                                    analyzer.sanitized_vars.add(node.name)
                                    for param in param_names:
                                        analyzer.sanitized_vars.add(param)
                                    
                                    # Add to flow graph
                                    sanitization_id = f"sanitize_func_regex_{node.lineno}"
                                    analyzer.flow_graph.add_node(sanitization_id, 
                                                              type='sanitization',
                                                              check_type='function_regex',
                                                              line=node.lineno)
                                    
                                    # Connect to all variables
                                    for var in ast.walk(node):
                                        if isinstance(var, ast.Name) and isinstance(var.ctx, ast.Store):
                                            var_name = var.id
                                            analyzer.sanitized_vars.add(var_name)
                                            if var_name in analyzer.flow_graph:
                                                analyzer.flow_graph.add_edge(sanitization_id, var_name, type='sanitized_flow')
                                    break
    
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
        # Parent node tracking
        self.parent_map = {}

        # Add untrusted sources to the graph
        for var in untrusted_vars:
            self.flow_graph.add_node(var, type='source', tainted=True)
            
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
        debug = os.environ.get('DEBUG') == "1"
        if debug and marked_vars:
            print(f"Marked variables as sanitized: {marked_vars}")
            
    def _find_containing_function(self, node):
        """Find the function containing the given node."""
        # Start from parent and go up looking for a FunctionDef node
        parent = getattr(node, 'parent', None)
        while parent is not None:
            if isinstance(parent, ast.FunctionDef):
                return parent
            parent = getattr(parent, 'parent', None)
        return None

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

    def _is_path_sanitized(self, path):
        """Check if a path contains a sanitization node or involves sanitized variables."""
        # Check if the path contains a sanitization point directly
        direct_sanitization = any(
            isinstance(node, str) and (
                node.startswith('sanitize_') or 
                node in self.sanitized_vars
            )
            for node in path
        )
        
        if direct_sanitization:
            return True
        
        # Check for sanitization relationships in the path
        # This handles cases where sanitization wasn't directly in the path
        # but affects variables in the path
        for i, node in enumerate(path[:-1]):
            if node in self.tainted_vars:
                # For each tainted node, check if it's connected to a sanitization node
                # that might not be directly in the path
                for sanitize_node in self.flow_graph.nodes():
                    if isinstance(sanitize_node, str) and sanitize_node.startswith('sanitize_'):
                        # Check if this sanitization node affects any variable in our path
                        for successor in self.flow_graph.successors(sanitize_node):
                            if successor in path[i:]:
                                return True
        
        # No sanitization found
        return False

    def analyze_vulnerabilities(self):
        """Analyze the code for straight paths from untrusted inputs through LLMs to outputs."""
        # Track unique vulnerabilities to avoid duplicates
        unique_vulnerabilities = set()
        
        # Extract sanitization nodes
        sanitization_nodes = [node for node in self.flow_graph.nodes() 
                             if isinstance(node, str) and node.startswith('sanitize_')]
        
        # Identify LLM API calls in the code (potential sinks)
        llm_call_nodes = [node for node in self.flow_graph.nodes() 
                         if isinstance(node, str) and node.startswith('llm_call_')]
        
        # Debug print sanitation points and nodes
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print(f"Found {len(sanitization_nodes)} sanitization nodes: {sanitization_nodes}")
            print(f"Found {len(self.sanitization_points)} sanitization points")
            print(f"Sanitized variables: {self.sanitized_vars}")
        
        # Find all inputs to LLM API calls
        for llm_node in llm_call_nodes:
            # Get predecessors (inputs to the LLM call)
            llm_inputs = list(self.flow_graph.predecessors(llm_node))
            
            # Check each input for taint
            for input_var in llm_inputs:
                if isinstance(input_var, str) and input_var in self.tainted_vars:
                    # Skip if this input is in our sanitized variables list
                    if input_var in self.sanitized_vars:
                        continue
                        
                    # This is a tainted input to an LLM - trace back to the source
                    for source in self.untrusted_vars:
                        if source in self.flow_graph:
                            try:
                                # Find all paths from untrusted source to this input
                                source_paths = list(nx.all_simple_paths(self.flow_graph, source, input_var))
                                
                                # Skip if no paths found
                                if not source_paths:
                                    continue
                                    
                                # Check if any path is sanitized
                                all_sanitized = True
                                for path in source_paths:
                                    if not self._is_path_sanitized(path):
                                        all_sanitized = False
                                        break
                                
                                if all_sanitized:
                                    # All paths are sanitized, no vulnerability
                                    continue
                                
                                # Create a vulnerability for this unsanitized source->LLM path
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
                    
                    # Skip if this is in sanitized variables
                    if var in self.sanitized_vars:
                        continue
                        
                    # This variable comes from sys.argv - check if it flows to an LLM
                    for llm_node in llm_call_nodes:
                        # Find paths from this variable to any LLM call
                        if var in self.flow_graph and llm_node in self.flow_graph:
                            try:
                                paths = list(nx.all_simple_paths(self.flow_graph, var, llm_node))
                                
                                # Skip if no paths found
                                if not paths:
                                    continue
                                
                                # Check if all paths are sanitized
                                all_sanitized = True
                                for path in paths:
                                    if not self._is_path_sanitized(path):
                                        all_sanitized = False
                                        break
                                
                                if all_sanitized:
                                    # All paths are sanitized, no vulnerability
                                    continue
                                
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
                        
                        # Skip if no valid paths
                        if not llm_paths:
                            continue
                            
                        # Check if all paths are sanitized
                        all_sanitized = True
                        for path in llm_paths:
                            if not self._is_path_sanitized(path):
                                all_sanitized = False
                                break
                        
                        if all_sanitized:
                            # All paths are sanitized, no vulnerability
                            continue
                            
                        # Found at least one unsanitized path
                        vuln_id = f"{source}_{output}"
                        
                        if vuln_id not in unique_vulnerabilities:
                            unique_vulnerabilities.add(vuln_id)
                            # Find the first unsanitized path to report
                            unsanitized_path = next(
                                (path for path in llm_paths if not self._is_path_sanitized(path)),
                                llm_paths[0]
                            )
                            self.vulnerabilities.append({
                                'type': 'llm_straight_path',
                                'source': source,
                                'sink': output,
                                'path': unsanitized_path,
                                'description': f"Straight path from untrusted input '{source}' through LLM to output '{output}'"
                            })
                                
                    except nx.NetworkXNoPath:
                        # No path exists
                        pass

        return self.vulnerabilities