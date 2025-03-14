"""
Scanner for detecting unsafe usage of LLM outputs.

This scanner identifies code patterns where LLM-generated content is passed to
functions that could execute code (e.g., eval, exec, os.system) without proper
validation, potentially leading to remote code execution vulnerabilities.
"""

import ast
import os
from typing import List, Dict, Set, Any, Optional, Tuple

from scanners.base_scanner import BaseScanner
from core.base_visitor import BaseVisitor
from core.issue import Issue
from core.ast_utils import get_function_name, get_attribute_chain
from rules.output.unsafe_execution_rule import UnsafeExecutionRule
from core.config import LLM_API_PATTERNS


class UnsafeOutputVisitor(BaseVisitor):
    """AST visitor that tracks LLM output variables and their usage in unsafe functions."""
    
    def __init__(self, context: Optional[Dict[str, Any]] = None):
        super().__init__(context)
        self.llm_output_vars = set()  # Set of variables containing LLM outputs
        self.unsafe_function_calls = []  # List of calls to potentially unsafe functions
        self.tainted_vars = set()  # Variables derived from LLM outputs
        self.llm_api_patterns = LLM_API_PATTERNS  # Import from shared config
        
        # Track function definitions that return LLM output
        self.llm_output_functions = set()
        
        # Track sanitized variables (variables that were tainted but have been sanitized)
        self.sanitized_vars = set()
        
        # Track sanitization points
        self.sanitization_points = []
        
        # Functions that are considered unsafe
        self.unsafe_functions = [
            "eval", "exec", "execfile",                         # Python eval/exec
            "os.system", "os.popen", "os.spawn", "os.exec",     # OS commands
            "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",  # subprocess
            "run_shell", "execute_command", "shell_exec",       # Common wrapper names
        ]
        
        # Functions that are considered sanitizers
        self.sanitization_functions = [
            "sanitize", "validate", "clean", "escape", "filter",
            "check_", "verify", "is_safe", "is_valid", "is_allowed"
        ]
    
    def visit_FunctionDef(self, node):
        """Track function definitions that return LLM output."""
        # First visit the body
        old_scope = self.tainted_vars.copy()
        super().visit_FunctionDef(node)
        
        # Check if this function returns LLM output
        # Look for return statements in the function body
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and self._is_expression_tainted(child.value):
                self.llm_output_functions.add(node.name)
                if os.environ.get('DEBUG') == "1":
                    print(f"Found function returning LLM output: {node.name} at line {node.lineno}")
                break
        
        # Restore scope
        self.tainted_vars = old_scope
    
    def visit_Assign(self, node):
        """Track assignments that contain LLM output."""
        super().visit_Assign(node)
        
        # Check if the right side of the assignment is tainted or an LLM call
        is_tainted = self._is_expression_tainted(node.value)
        is_llm_call = isinstance(node.value, ast.Call) and self._is_llm_call(node.value)
        
        if is_tainted or is_llm_call:
            # Mark all target variables as tainted
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    if is_llm_call:
                        self.llm_output_vars.add(target.id)
                    if os.environ.get('DEBUG') == "1":
                        print(f"Found tainted variable: {target.id} at line {node.lineno}")
        
        # Handle cases where we're extracting content from an LLM response
        # This catches patterns like 'llm_code = response.choices[0].message.content'
        for target in node.targets:
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Attribute):
                attr_chain = get_attribute_chain(node.value)
                # Check for common response content extraction patterns
                if any(attr in ["content", "completion", "text", "output", "result"] for attr in attr_chain):
                    # If the parent variable is in a common response pattern or is tainted
                    base_var = attr_chain[0] if attr_chain else ""
                    if base_var in self.tainted_vars or base_var in ["response", "completion", "result", "output"]:
                        self.tainted_vars.add(target.id)
                        self.llm_output_vars.add(target.id)
                        if os.environ.get('DEBUG') == "1":
                            print(f"Found LLM output extraction: {target.id} = {'.'.join(attr_chain)} at line {node.lineno}")
    
    def visit_Call(self, node):
        """Track calls to unsafe functions and sanitization functions."""
        super().visit_Call(node)
        
        # Get the function name
        func_name = self._get_full_function_name(node)
        
        # Handle sanitization calls first
        if any(sanitize_name in func_name.lower() for sanitize_name in self.sanitization_functions):
            # This call might be a sanitization function
            self._handle_sanitization_call(node, func_name)
            
        # Then check for unsafe function calls
        elif any(unsafe in func_name for unsafe in self.unsafe_functions):
            # Check if any argument is tainted and not sanitized
            for arg in node.args:
                if self._is_expression_tainted(arg) and not self._is_sanitized(arg):
                    self.unsafe_function_calls.append((node, arg))
                    if os.environ.get('DEBUG') == "1":
                        arg_desc = f"{arg.id}" if isinstance(arg, ast.Name) else f"expression at line {arg.lineno}"
                        print(f"VULNERABILITY: Tainted value {arg_desc} passed to {func_name} at line {node.lineno}")
            
            # Check keyword arguments too
            for kw in node.keywords:
                if self._is_expression_tainted(kw.value) and not self._is_sanitized(kw.value):
                    self.unsafe_function_calls.append((node, kw.value))
                    if os.environ.get('DEBUG') == "1":
                        arg_desc = f"{kw.value.id}" if isinstance(kw.value, ast.Name) else f"expression at line {kw.value.lineno}"
                        print(f"VULNERABILITY: Tainted value {arg_desc} passed to {func_name} as {kw.arg} at line {node.lineno}")
            
            if not any(self._is_expression_tainted(arg) for arg in node.args) and \
               not any(self._is_expression_tainted(kw.value) for kw in node.keywords):
                # Still track unsafe function calls without tainted arguments
                self.unsafe_function_calls.append((node, None))
                if os.environ.get('DEBUG') == "1":
                    print(f"Found unsafe function call: {func_name} at line {node.lineno}")
    
    def _handle_sanitization_call(self, node, func_name):
        """Process sanitization function calls and mark sanitized variables."""
        sanitization_id = f"sanitize_call_{node.lineno}"
        
        # Check if this call is assigned to a variable
        parent = getattr(node, 'parent', None)
        assign_targets = []
        
        # If this call is within an assignment, get the target variables
        if isinstance(parent, ast.Assign):
            assign_targets = [target.id for target in parent.targets if isinstance(target, ast.Name)]
        
        # If this is a validation function in a condition (e.g., if validate_expression(expr)),
        # find what's being validated
        elif isinstance(parent, ast.If) and parent.test == node:
            # This is a validation check in an if condition
            # Look for unsafe calls in the body with the same arguments
            tainted_arg_names = []
            for arg in node.args:
                if isinstance(arg, ast.Name) and self._is_expression_tainted(arg):
                    tainted_arg_names.append(arg.id)
            
            # If we found tainted arguments, check if they're used safely in the body
            if tainted_arg_names:
                for child in parent.body:
                    # Check for unsafe function calls in the body
                    for unsafe_node in ast.walk(child):
                        if isinstance(unsafe_node, ast.Call):
                            unsafe_func = self._get_full_function_name(unsafe_node)
                            if any(unsafe in unsafe_func for unsafe in self.unsafe_functions):
                                # Check if any of the tainted args are used here
                                for arg in unsafe_node.args:
                                    if isinstance(arg, ast.Name) and arg.id in tainted_arg_names:
                                        # This is a validation function that protects an unsafe call
                                        # Mark the argument as sanitized
                                        self.sanitized_vars.add(arg.id)
                                        if os.environ.get('DEBUG') == "1":
                                            print(f"Sanitized variable: {arg.id} (via validation function {func_name}) at line {node.lineno}")
                                        
                                        # Record this sanitization
                                        self.sanitization_points.append({
                                            'node': node,
                                            'function': func_name,
                                            'line': node.lineno,
                                            'tainted_args': [arg.id],
                                            'sanitized_vars': [arg.id],
                                            'description': f"Validation function {func_name} verifies before unsafe call"
                                        })
            
        # Process arguments to see what's being sanitized
        tainted_args = []
        for arg in node.args:
            if self._is_expression_tainted(arg):
                tainted_args.append(arg)
                if isinstance(arg, ast.Name):
                    # If a tainted variable is directly passed to a sanitization function,
                    # consider any assigned variables as sanitized
                    for target in assign_targets:
                        self.sanitized_vars.add(target)
                        if os.environ.get('DEBUG') == "1":
                            print(f"Sanitized variable: {target} (from {arg.id}) at line {node.lineno}")
        
        # Record this sanitization point if tainted arguments were processed
        if tainted_args and assign_targets:
            self.sanitization_points.append({
                'node': node,
                'function': func_name,
                'line': node.lineno,
                'tainted_args': [arg.id if isinstance(arg, ast.Name) else f"expr_{node.lineno}" for arg in tainted_args],
                'sanitized_vars': assign_targets,
                'description': f"Sanitization function {func_name} applied to tainted input"
            })
            if os.environ.get('DEBUG') == "1":
                print(f"Found sanitization call: {func_name} at line {node.lineno}")
                
        return bool(tainted_args and assign_targets)
    
    def visit_If(self, node):
        """Handle if statements that might contain sanitization checks."""
        # Process the test condition first
        self.generic_visit(node.test)
        
        # Check if the test condition is a sanitization check
        is_sanitization = False
        sanitized_vars = set()
        
        # Check if this is a safety check by looking at variable names
        safety_check_names = ['is_safe', 'safe', 'valid', 'validated', 'allowed', 'permitted',
                             'check', 'verified', 'sanitized', 'clean']
        
        # Check if the condition is a simple variable with a safety name
        # e.g., if is_safe: ...
        if isinstance(node.test, ast.Name):
            if any(safety_name in node.test.id.lower() for safety_name in safety_check_names):
                is_sanitization = True
                
                # Find variables to sanitize in the body
                for child in node.body:
                    if isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                        if any(unsafe in self._get_full_function_name(child.value) for unsafe in self.unsafe_functions):
                            # Find any tainted arguments
                            for arg in child.value.args:
                                if isinstance(arg, ast.Name) and self._is_expression_tainted(arg):
                                    sanitized_vars.add(arg.id)
        
        # Check for membership tests (in operator)
        elif isinstance(node.test, ast.Compare):
            for i, op in enumerate(node.test.ops):
                if isinstance(op, ast.In):
                    left = node.test.left if i == 0 else node.test.comparators[i-1]
                    right = node.test.comparators[i]
                    
                    # If checking if a tainted value is in an allowlist/whitelist
                    if self._is_expression_tainted(left) and not self._is_expression_tainted(right):
                        # This is a sanitization check
                        sanitization_id = f"sanitize_if_{node.lineno}"
                        is_sanitization = True
                        
                        # Find variables that are used in the tainted expression
                        if isinstance(left, ast.Name):
                            sanitized_vars.add(left.id)
        
        # Process the body of the if statement
        if is_sanitization:
            # Save current sanitized state
            old_sanitized = self.sanitized_vars.copy()
            
            # Mark variables as sanitized within this branch
            for var in sanitized_vars:
                self.sanitized_vars.add(var)
                if os.environ.get('DEBUG') == "1":
                    print(f"Sanitized variable: {var} (from if-in check) at line {node.lineno}")
            
            # Process the body with these variables sanitized
            for child in node.body:
                self.visit(child)
                
            # Record this sanitization point
            self.sanitization_points.append({
                'node': node,
                'check_type': 'if_membership',
                'line': node.lineno,
                'sanitized_vars': list(sanitized_vars),
                'description': f"If statement with membership check sanitizes input"
            })
            
            # Restore original sanitized state (sanitization only applies within the if block)
            self.sanitized_vars = old_sanitized
        else:
            # Just process the body normally
            for child in node.body:
                self.visit(child)
                
        # Process the else branch normally
        if node.orelse:
            for child in node.orelse:
                self.visit(child)
    
    def visit_Compare(self, node):
        """Handle comparison operations that might act as sanitization checks."""
        self.generic_visit(node)
        
        # Check for sanitization patterns like regex matching
        if any(isinstance(op, ast.In) for op in node.ops):
            # This is handled by visit_If when it's part of an if statement
            pass
        elif any(isinstance(op, (ast.Eq, ast.Is)) for op in node.ops):
            # Check for equality comparisons against allowed values
            # (Not implementing this here as it's a bit complex - would need to track what's being compared)
            pass
    
    def visit_Subscript(self, node):
        """Handle dictionary lookups which can act as sanitization."""
        self.generic_visit(node)
        
        # Check for pattern where tainted input is used as a dictionary key
        # e.g., allowed_commands[user_input] - this is a form of sanitization
        if isinstance(node.value, ast.Name) and self._is_expression_tainted(node.slice):
            # This is potentially a sanitization pattern
            container_name = node.value.id
            
            # Dictionary names that suggest allowlists/whitelists
            allowlist_names = ['allowed', 'whitelist', 'valid', 'safe', 'permitted']
            
            is_allowlist = any(pattern in container_name.lower() for pattern in allowlist_names)
            
            # Find parent assignment if any
            parent = getattr(node, 'parent', None)
            if isinstance(parent, ast.Assign) and is_allowlist:
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        # Mark this variable as sanitized
                        self.sanitized_vars.add(target.id)
                        if os.environ.get('DEBUG') == "1":
                            print(f"Sanitized variable: {target.id} (from allowlist lookup) at line {node.lineno}")
                        
                        # Record this sanitization point
                        self.sanitization_points.append({
                            'node': node,
                            'check_type': 'container_lookup',
                            'line': node.lineno,
                            'container': container_name,
                            'sanitized_vars': [target.id],
                            'description': f"Allowlist lookup in '{container_name}' sanitizes input"
                        })
    
    def _is_sanitized(self, node):
        """Check if an expression has been sanitized."""
        if node is None:
            return False
            
        # Simple case: variable is in sanitized_vars
        if isinstance(node, ast.Name):
            return node.id in self.sanitized_vars
            
        # Recursively check components of complex expressions
        for child in ast.iter_child_nodes(node):
            if not self._is_sanitized(child):
                return False
                
        return True
    
    def _is_expression_tainted(self, node):
        """Check if an expression contains tainted variables."""
        if node is None:
            return False
            
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars or node.id in self.llm_output_vars
        elif isinstance(node, ast.Call):
            # Check if this is a call to a function that returns LLM output
            if isinstance(node.func, ast.Name) and node.func.id in self.llm_output_functions:
                return True
                
            # Or it's a direct LLM call
            if self._is_llm_call(node):
                return True
                
            # Check all arguments
            for arg in node.args:
                if self._is_expression_tainted(arg):
                    return True
            for kw in node.keywords:
                if self._is_expression_tainted(kw.value):
                    return True
        elif isinstance(node, ast.BinOp):
            # Check binary operations like string concatenation
            return self._is_expression_tainted(node.left) or self._is_expression_tainted(node.right)
        elif isinstance(node, ast.Attribute):
            # For attribute access, check if the base is tainted
            if isinstance(node.value, ast.Name):
                return node.value.id in self.tainted_vars or node.value.id in self.llm_output_vars
            # Check for nested attributes
            return self._is_expression_tainted(node.value)
        elif isinstance(node, ast.Subscript):
            # Handle subscripts (indexing)
            return self._is_expression_tainted(node.value) or self._is_expression_tainted(node.slice)
        elif isinstance(node, ast.Slice):
            # Handle slice objects specifically
            tainted = False
            if hasattr(node, 'lower') and node.lower:
                tainted = tainted or self._is_expression_tainted(node.lower)
            if hasattr(node, 'upper') and node.upper:
                tainted = tainted or self._is_expression_tainted(node.upper)
            if hasattr(node, 'step') and node.step:
                tainted = tainted or self._is_expression_tainted(node.step)
            return tainted
        
        # Recursively check all child nodes
        for child in ast.iter_child_nodes(node):
            if self._is_expression_tainted(child):
                return True
                
        return False
    
    def _is_llm_call(self, node):
        """Check if a call node is an LLM API call."""
        if not isinstance(node, ast.Call):
            return False
        
        # Check if this is a recognized LLM API call pattern
        func_name = self._get_full_function_name(node)
        
        # Common LLM API function names
        llm_function_keywords = [
            "complete", "completion", "chat", "generate", "predict", 
            "create", "messages", "prompt", "llm", "ai", "gpt"
        ]
        
        # Direct check for common patterns like openai.create, anthropic.complete
        if any(api in func_name for api in ["openai", "anthropic", "ai21", "cohere"]) and \
           any(kw in func_name.lower() for kw in llm_function_keywords):
            return True
        
        # Check method chains via the shared LLM_API_PATTERNS
        if isinstance(node.func, ast.Attribute):
            attr_chain = get_attribute_chain(node.func)
            # Check against the method chain patterns
            for pattern_group in self.llm_api_patterns:
                if pattern_group.get('type') == 'method_chain':
                    for pattern in pattern_group.get('patterns', []):
                        obj = pattern.get('object', '')
                        attrs = pattern.get('attrs', [])
                        if attr_chain and attr_chain[0] == obj and all(attr in attr_chain for attr in attrs):
                            return True
        
        # Check simple function names
        if isinstance(node.func, ast.Name):
            for pattern_group in self.llm_api_patterns:
                if pattern_group.get('type') == 'function':
                    if node.func.id in pattern_group.get('names', []):
                        return True
        
        return False
    
    def _get_full_function_name(self, node):
        """Get the full function name including module path."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return ".".join(get_attribute_chain(node.func))
        return ""


class UnsafeExecutionScanner(BaseScanner):
    """Scanner for detecting unsafe usage of LLM outputs."""
    
    def __init__(self):
        """Initialize the scanner with the UnsafeExecutionRule."""
        rules = [
            UnsafeExecutionRule()
        ]
        super().__init__(rules)
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan AST for unsafe LLM output usage patterns."""
        context = context or {}
        self.reset()  # Clear any previous issues
        
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print(f"UnsafeExecutionScanner scanning file: {context.get('file_name', 'unknown')}")
        
        # Use our visitor to track LLM outputs and unsafe function calls
        visitor = UnsafeOutputVisitor(context)
        
        # Set parent references to help with context detection
        for node in ast.walk(ast_node):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        
        visitor.visit(ast_node)
        
        # Add the LLM output variables to the context
        context["llm_output_vars"] = visitor.llm_output_vars
        
        if debug:
            print(f"Found {len(visitor.llm_output_vars)} LLM output variables: {visitor.llm_output_vars}")
            print(f"Found {len(visitor.unsafe_function_calls)} unsafe function calls")
            if visitor.sanitized_vars:
                print(f"Found {len(visitor.sanitized_vars)} sanitized variables: {visitor.sanitized_vars}")
            if visitor.sanitization_points:
                print(f"Found {len(visitor.sanitization_points)} sanitization points")
                
        # Record all scanned elements for comprehensive reporting
        file_name = context.get('file_name', 'unknown')
        
        # Record all LLM output variables
        for var_name in visitor.llm_output_vars:
            # Find where this variable was defined
            line_num = 0
            if var_name in visitor.variables:
                line_num = visitor.variables[var_name].get("line", 0)
            
            self.record_scanned_element("llm_outputs", {
                "variable_name": var_name,
                "line_number": line_num,
                "is_sanitized": var_name in visitor.sanitized_vars,
                "file": file_name
            })
        
        # Record all unsafe function calls, including those that were deemed safe
        for call_node, tainted_arg in visitor.unsafe_function_calls:
            if tainted_arg:  # Only include calls with tainted arguments
                func_name = visitor._get_full_function_name(call_node)
                arg_desc = ""
                if isinstance(tainted_arg, ast.Name):
                    arg_desc = tainted_arg.id
                else:
                    arg_desc = f"expression at line {getattr(tainted_arg, 'lineno', call_node.lineno)}"
                
                # Check if this call is sanitized (inside validation or with sanitized args)
                is_sanitized = visitor._is_sanitized(tainted_arg)
                
                # Check if inside validation block
                inside_validation = False
                node = call_node
                while hasattr(node, 'parent'):
                    parent = getattr(node, 'parent', None)
                    if parent is None:
                        break
                    if isinstance(parent, ast.If):
                        cond_str = ast.unparse(parent.test) if hasattr(ast, 'unparse') else str(parent.test)
                        safety_keywords = ['safe', 'valid', 'sanitized', 'allowed', 'whitelisted', 'permitted']
                        if any(keyword in cond_str.lower() for keyword in safety_keywords):
                            inside_validation = True
                            break
                    node = parent
                
                self.record_scanned_element("unsafe_calls", {
                    "function": func_name,
                    "argument": arg_desc,
                    "line_number": call_node.lineno,
                    "is_sanitized": is_sanitized or inside_validation,
                    "inside_validation_block": inside_validation,
                    "file": file_name
                })
        
        # Create synthetic issues for detected vulnerabilities
        for call_node, tainted_arg in visitor.unsafe_function_calls:
            if not tainted_arg:  # Skip if no tainted argument
                continue
                
            # Skip if this call is inside a validation check
            inside_validation = False
            
            # Check if the unsafe call is inside a sanitization if-block
            node = call_node
            while hasattr(node, 'parent'):
                parent = getattr(node, 'parent', None)
                if parent is None:
                    break
                    
                # If parent is an If node with a sanitization condition
                if isinstance(parent, ast.If):
                    # Check if the condition contains safety checks
                    cond_str = ast.unparse(parent.test) if hasattr(ast, 'unparse') else str(parent.test)
                    safety_keywords = ['safe', 'valid', 'sanitized', 'allowed', 'whitelisted', 'permitted', 
                                      'validate', 'check', 'is_', 'has_']
                    
                    if any(keyword in cond_str.lower() for keyword in safety_keywords):
                        inside_validation = True
                        if debug:
                            print(f"Skipping issue at line {call_node.lineno} because it's inside a validation block")
                        break
                
                node = parent
                
            if inside_validation:
                continue
                
            # Skip if the tainted argument itself is sanitized
            if visitor._is_sanitized(tainted_arg):
                if debug:
                    arg_desc = tainted_arg.id if isinstance(tainted_arg, ast.Name) else f"expression at line {call_node.lineno}"
                    print(f"Skipping issue at line {call_node.lineno} because argument {arg_desc} is sanitized")
                continue
            
            # Create the issue
            func_name = visitor._get_full_function_name(call_node)
            arg_desc = ""
            if isinstance(tainted_arg, ast.Name):
                arg_desc = tainted_arg.id
            else:
                arg_desc = f"expression at line {getattr(tainted_arg, 'lineno', call_node.lineno)}"
            
            issue = Issue(
                rule_id="output-unsafe-execution",
                message=f"LLM output '{arg_desc}' is passed to unsafe function '{func_name}'",
                location={
                    "file": context.get("file_name", "<unknown>"),
                    "line": call_node.lineno,
                    "column": call_node.col_offset
                },
                severity="critical",
                fix_suggestion="Validate and sanitize LLM outputs before passing to potentially dangerous functions. Never directly execute LLM-generated code.",
                context={
                    "function": func_name,
                    "tainted_arg": arg_desc
                }
            )
            self.register_issue(issue)
        
        if debug:
            print(f"Final count of issues: {len(self.issues)}")
        
        return self.issues