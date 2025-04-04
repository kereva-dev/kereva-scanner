"""
Scanner for enforcing safe shell command execution with LLM outputs.

This scanner identifies code patterns where LLM-generated content is passed to
shell functions and verifies if the commands and arguments are on a pre-defined allowlist.
"""

import ast
import os
from typing import List, Dict, Set, Any, Optional

from scanners.base_scanner import BaseScanner
from core.base_visitor import BaseVisitor
from core.issue import Issue
from core.ast_utils import get_function_name, get_attribute_chain
from core.config import SHELL_EXECUTION_FUNCTIONS, SAFE_SHELL_COMMANDS, LLM_API_PATTERNS
from rules.output.safe_shell_commands_rule import SafeShellCommandsRule


class SafeShellCommandsVisitor(BaseVisitor):
    """AST visitor that tracks LLM output variables and their usage in shell commands."""
    
    def __init__(self, context: Optional[Dict[str, Any]] = None):
        super().__init__(context)
        self.llm_output_vars = set()  # Set of variables containing LLM outputs
        self.shell_command_calls = []  # List of calls to shell functions
        self.tainted_vars = set()  # Variables derived from LLM outputs
        self.llm_api_patterns = LLM_API_PATTERNS  # Import from shared config
        
        # Track function definitions that return LLM output
        self.llm_output_functions = set()
        
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
        """Track calls to shell command functions."""
        super().visit_Call(node)
        
        # Get the function name
        func_name = self._get_full_function_name(node)
        
        if os.environ.get('DEBUG') == "1":
            print(f"Visiting call: {func_name} at line {getattr(node, 'lineno', 'unknown')}")
        
        # Check if this is a shell execution function
        if any(shell_func in func_name for shell_func in SHELL_EXECUTION_FUNCTIONS):
            has_tainted_arg = False
            
            # Check if any argument is tainted
            for i, arg in enumerate(node.args):
                if self._is_expression_tainted(arg):
                    has_tainted_arg = True
                    self.shell_command_calls.append((node, arg))
                    if os.environ.get('DEBUG') == "1":
                        arg_desc = f"{arg.id}" if isinstance(arg, ast.Name) else f"expression at line {arg.lineno}"
                        print(f"Found shell command with tainted value {arg_desc} at line {node.lineno}")
            
            # Check keyword arguments too
            for kw in node.keywords:
                if self._is_expression_tainted(kw.value):
                    has_tainted_arg = True
                    self.shell_command_calls.append((node, kw.value))
                    if os.environ.get('DEBUG') == "1":
                        arg_desc = f"{kw.value.id}" if isinstance(kw.value, ast.Name) else f"expression at line {kw.value.lineno}"
                        print(f"Found shell command with tainted value {arg_desc} as {kw.arg} at line {node.lineno}")
                        
            # For the direct LLM output case (like os.system(llm_command)), we need to check if
            # any argument is a direct LLM output variable
            if not has_tainted_arg and len(node.args) > 0:
                for i, arg in enumerate(node.args):
                    if isinstance(arg, ast.Name) and arg.id in self.llm_output_vars:
                        self.shell_command_calls.append((node, arg))
                        if os.environ.get('DEBUG') == "1":
                            print(f"Found direct shell command with LLM output {arg.id} at line {node.lineno}")
                            
            # If we still found no tainted arguments but this is a shell execution function
            # record it with a None argument to be checked anyway by rules
            if not self.shell_command_calls and len(node.args) > 0:
                self.shell_command_calls.append((node, None))
                if os.environ.get('DEBUG') == "1":
                    print(f"Found shell command function call (with no tainted args) at line {node.lineno}")
    
    def _is_expression_tainted(self, node):
        """Check if an expression contains tainted variables."""
        if node is None:
            return False
        
        if os.environ.get('DEBUG') == "1":
            node_type = type(node).__name__
            print(f"Checking if expression is tainted: {node_type} at line {getattr(node, 'lineno', 'unknown')}")
            
        if isinstance(node, ast.Name):
            is_tainted = node.id in self.tainted_vars or node.id in self.llm_output_vars
            if is_tainted and os.environ.get('DEBUG') == "1":
                print(f"Found tainted variable in expression: {node.id}")
            return is_tainted
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
        elif isinstance(node, ast.JoinedStr):
            # Handle f-strings
            for value in node.values:
                if isinstance(value, ast.FormattedValue) and self._is_expression_tainted(value.value):
                    if os.environ.get('DEBUG') == "1":
                        print(f"Found tainted variable in f-string at line {getattr(node, 'lineno', 'unknown')}")
                    return True
        elif isinstance(node, ast.FormattedValue):
            # Handle the formatted values in f-strings
            return self._is_expression_tainted(node.value)
        
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


class SafeShellCommandsScanner(BaseScanner):
    """Scanner for enforcing safe shell command execution with LLM outputs."""
    
    def __init__(self):
        """Initialize the scanner with the SafeShellCommandsRule."""
        rules = [
            SafeShellCommandsRule()
        ]
        super().__init__(rules)
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan AST for shell command execution with LLM outputs."""
        context = context or {}
        self.reset()  # Clear any previous issues
        
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print(f"SafeShellCommandsScanner scanning file: {context.get('file_name', 'unknown')}")
        
        # Use our visitor to track LLM outputs and shell command calls
        visitor = SafeShellCommandsVisitor(context)
        
        # Set parent references to help with context detection
        for node in ast.walk(ast_node):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        
        visitor.visit(ast_node)
        
        # Merge LLM output variables from context with those found by the visitor
        if "llm_output_vars" in context:
            # If vars are provided in context (like in tests), add them to the visitor's set
            visitor.llm_output_vars.update(context["llm_output_vars"])
        
        # Update the context with the complete set of LLM output variables and tainted variables
        context["llm_output_vars"] = visitor.llm_output_vars
        context["tainted_vars"] = visitor.tainted_vars
        
        # Add all variables that were detected in shell command calls to tainted vars
        tainted_command_vars = set()
        
        # First, add any variables returned by LLM-related functions
        for func_name in visitor.llm_output_functions:
            # For each function that returns LLM output, look for variables that store its result
            for var_name, var_info in visitor.variables.items():
                if var_info.get("source") == func_name:
                    tainted_command_vars.add(var_name)
                    if debug:
                        print(f"Adding {var_name} to tainted vars because it stores result of {func_name}")
                    
        # Add variables directly from the shell command calls
        for call_node, tainted_arg in visitor.shell_command_calls:
            if tainted_arg and isinstance(tainted_arg, ast.Name):
                tainted_command_vars.add(tainted_arg.id)
        
        # Add these to both visitor and context
        visitor.tainted_vars.update(tainted_command_vars)
        context["tainted_vars"] = visitor.tainted_vars
        
        if debug:
            print(f"Found {len(visitor.llm_output_vars)} LLM output variables: {visitor.llm_output_vars}")
            print(f"Found {len(visitor.tainted_vars)} tainted variables: {visitor.tainted_vars}")
            print(f"Found {len(visitor.shell_command_calls)} shell command calls")
                
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
                "file": file_name
            })
        
        # Record all shell command calls
        for call_node, tainted_arg in visitor.shell_command_calls:
            if tainted_arg:  # Only include calls with tainted arguments
                func_name = visitor._get_full_function_name(call_node)
                arg_desc = ""
                if isinstance(tainted_arg, ast.Name):
                    arg_desc = tainted_arg.id
                else:
                    arg_desc = f"expression at line {getattr(tainted_arg, 'lineno', call_node.lineno)}"
                
                self.record_scanned_element("shell_commands", {
                    "function": func_name,
                    "argument": arg_desc,
                    "line_number": call_node.lineno,
                    "file": file_name
                })
        
        # Apply our rule to each shell command call with tainted arguments
        for call_node, tainted_arg in visitor.shell_command_calls:
            if debug:
                print(f"Applying rules to shell command call at line {getattr(call_node, 'lineno', 'unknown')}")
                if tainted_arg:
                    arg_desc = f"{tainted_arg.id}" if isinstance(tainted_arg, ast.Name) else "expression"
                    print(f"  With tainted argument: {arg_desc}")
                
            # Make sure the context has what the rule needs
            # We don't need to set the code attribute; the analyzer should handle that
                
            # Apply rules to this call
            issues = self.apply_rules(call_node, context)
            
            if debug:
                print(f"  Found {len(issues)} issues in this call")
            
        return self.issues