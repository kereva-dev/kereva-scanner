"""
Scanner for detecting unsafe rendering of LLM outputs.

This scanner identifies code patterns where LLM-generated content is passed to
rendering functions (e.g., markdown, HTML, templates) without proper sanitization,
potentially leading to cross-site scripting (XSS) or other injection vulnerabilities.
"""

import ast
import os
from typing import List, Dict, Set, Any, Optional, Tuple

from scanners.base_scanner import BaseScanner
from core.base_visitor import BaseVisitor
from core.issue import Issue
from core.ast_utils import get_function_name, get_attribute_chain
from rules.output.unsafe_rendering_rule import UnsafeRenderingRule
from core.config import LLM_API_PATTERNS, UNSAFE_RENDERING_FUNCTIONS, RENDERING_SANITIZATION_FUNCTIONS


class UnsafeRenderingVisitor(BaseVisitor):
    """AST visitor that tracks LLM output variables and their usage in rendering functions."""
    
    def __init__(self, context: Optional[Dict[str, Any]] = None):
        super().__init__(context)
        self.llm_output_vars = set()  # Set of variables containing LLM outputs
        self.rendering_function_calls = []  # List of calls to potentially unsafe rendering functions
        self.tainted_vars = set()  # Variables derived from LLM outputs
        self.llm_api_patterns = LLM_API_PATTERNS  # Import from shared config
        
        # Track function definitions that return LLM output
        self.llm_output_functions = set()
        
        # Track sanitized variables (variables that were tainted but have been sanitized)
        self.sanitized_vars = set()
        
        # Track sanitization points
        self.sanitization_points = []
        
        # Import rendering functions from config
        self.unsafe_rendering_functions = UNSAFE_RENDERING_FUNCTIONS
        self.sanitization_functions = RENDERING_SANITIZATION_FUNCTIONS
        
        # Debug flag
        self.debug = os.environ.get('DEBUG') == "1"
    
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
                if self.debug:
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
                    if self.debug:
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
                        if self.debug:
                            print(f"Found LLM output extraction: {target.id} = {'.'.join(attr_chain)} at line {node.lineno}")
    
    def visit_Call(self, node):
        """Track calls to rendering functions and sanitization functions."""
        super().visit_Call(node)
        
        # Get the function name
        func_name = self._get_full_function_name(node)
        
        # Handle sanitization calls first
        if any(sanitize_name in func_name for sanitize_name in self.sanitization_functions):
            # This call might be a sanitization function
            self._handle_sanitization_call(node, func_name)
            
        # Then check for rendering function calls
        elif any(render_func in func_name for render_func in self.unsafe_rendering_functions):
            # Check if any argument is tainted and not sanitized
            for arg in node.args:
                if self._is_expression_tainted(arg) and not self._is_sanitized(arg):
                    self.rendering_function_calls.append((node, arg))
                    if self.debug:
                        arg_desc = f"{arg.id}" if isinstance(arg, ast.Name) else f"expression at line {arg.lineno}"
                        print(f"VULNERABILITY: Tainted value {arg_desc} passed to rendering function {func_name} at line {node.lineno}")
            
            # Check keyword arguments too
            for kw in node.keywords:
                if self._is_expression_tainted(kw.value) and not self._is_sanitized(kw.value):
                    self.rendering_function_calls.append((node, kw.value))
                    if self.debug:
                        arg_desc = f"{kw.value.id}" if isinstance(kw.value, ast.Name) else f"expression at line {kw.value.lineno}"
                        print(f"VULNERABILITY: Tainted value {arg_desc} passed to rendering function {func_name} as {kw.arg} at line {node.lineno}")
            
            if not any(self._is_expression_tainted(arg) for arg in node.args) and \
               not any(self._is_expression_tainted(kw.value) for kw in node.keywords):
                # Still track rendering function calls without tainted arguments
                self.rendering_function_calls.append((node, None))
                if self.debug:
                    print(f"Found rendering function call: {func_name} at line {node.lineno}")
    
    def _handle_sanitization_call(self, node, func_name):
        """Process sanitization function calls and mark sanitized variables."""
        sanitization_id = f"sanitize_call_{node.lineno}"
        
        # Check if this call is assigned to a variable
        parent = getattr(node, 'parent', None)
        assign_targets = []
        
        # If this call is within an assignment, get the target variables
        if isinstance(parent, ast.Assign):
            assign_targets = [target.id for target in parent.targets if isinstance(target, ast.Name)]
        
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
                        if self.debug:
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
            if self.debug:
                print(f"Found sanitization call: {func_name} at line {node.lineno}")
                
        return bool(tainted_args and assign_targets)
    
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


class UnsafeRenderingScanner(BaseScanner):
    """Scanner for detecting unsafe rendering of LLM outputs."""
    
    def __init__(self):
        """Initialize the scanner with the UnsafeRenderingRule."""
        rules = [
            UnsafeRenderingRule()
        ]
        super().__init__(rules)
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan AST for unsafe LLM output rendering patterns."""
        context = context or {}
        self.reset()  # Clear any previous issues
        
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print(f"UnsafeRenderingScanner scanning file: {context.get('file_name', 'unknown')}")
        
        # Use our visitor to track LLM outputs and rendering function calls
        visitor = UnsafeRenderingVisitor(context)
        
        # Set parent references to help with context detection
        for node in ast.walk(ast_node):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        
        visitor.visit(ast_node)
        
        # Add the LLM output variables to the context
        context["llm_output_vars"] = visitor.llm_output_vars
        context["sanitized_vars"] = visitor.sanitized_vars
        
        if debug:
            print(f"Found {len(visitor.llm_output_vars)} LLM output variables: {visitor.llm_output_vars}")
            print(f"Found {len(visitor.rendering_function_calls)} rendering function calls")
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
        
        # Record all rendering function calls, including those that were deemed safe
        for call_node, tainted_arg in visitor.rendering_function_calls:
            if tainted_arg:  # Only include calls with tainted arguments
                func_name = visitor._get_full_function_name(call_node)
                arg_desc = ""
                if isinstance(tainted_arg, ast.Name):
                    arg_desc = tainted_arg.id
                else:
                    arg_desc = f"expression at line {getattr(tainted_arg, 'lineno', call_node.lineno)}"
                
                # Check if this call is sanitized
                is_sanitized = visitor._is_sanitized(tainted_arg)
                
                self.record_scanned_element("rendering_calls", {
                    "function": func_name,
                    "argument": arg_desc,
                    "line_number": call_node.lineno,
                    "is_sanitized": is_sanitized,
                    "file": file_name
                })
        
        # Apply rules to each rendering function call with tainted arguments
        for call_node, tainted_arg in visitor.rendering_function_calls:
            if not tainted_arg:  # Skip if no tainted argument
                continue
                
            # Skip if the tainted argument is sanitized
            if visitor._is_sanitized(tainted_arg):
                if debug:
                    arg_desc = tainted_arg.id if isinstance(tainted_arg, ast.Name) else f"expression at line {call_node.lineno}"
                    print(f"Skipping issue at line {call_node.lineno} because argument {arg_desc} is sanitized")
                continue
            
            # Create an issue manually since we've already detected the vulnerability
            func_name = visitor._get_full_function_name(call_node)
            
            # Create a descriptive message
            arg_desc = ""
            if isinstance(tainted_arg, ast.Name):
                arg_desc = tainted_arg.id
            else:
                arg_desc = f"expression at line {getattr(tainted_arg, 'lineno', call_node.lineno)}"
            
            location = {
                "file": context.get("file_name", "<unknown>"),
                "line": call_node.lineno,
                "column": call_node.col_offset
            }
            
            # Create the issue
            issue = Issue(
                rule_id="output-unsafe-rendering",
                message=f"LLM output '{arg_desc}' is passed to rendering function '{func_name}' without proper sanitization",
                location=location,
                severity="high",
                fix_suggestion="Sanitize LLM outputs before passing to rendering functions to prevent XSS. Use libraries like bleach or html.escape to sanitize HTML or implement proper input validation.",
                context={
                    "function": func_name,
                    "tainted_arg": arg_desc,
                    "tainted_source": "LLM output"
                },
                tags=["security", "xss", "rendering", "sanitization"]
            )
            
            self.register_issue(issue)
        
        if debug:
            print(f"Final count of issues: {len(self.issues)}")
        
        return self.issues