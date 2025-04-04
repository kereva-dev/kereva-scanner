"""
Rule for detecting unsafe rendering of LLM outputs.

This module defines a rule that checks if LLM outputs are being passed
to rendering functions like markdown or HTML renderers without proper sanitization,
which could lead to cross-site scripting (XSS) or other injection vulnerabilities.
"""

import ast
from typing import Any, Optional, Dict, List, Set
from rules.base_rule import BaseRule
from core.issue import Issue
from core.ast_utils import get_function_name, get_attribute_chain

class UnsafeRenderingRule(BaseRule):
    """Rule to detect LLM outputs being passed to rendering functions without sanitization."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-unsafe-rendering",
            description="LLM output is passed to rendering function without proper sanitization",
            severity="high",
            tags=["security", "xss", "rendering", "sanitization"]
        )
        
        # Import patterns from config
        from core.config import UNSAFE_RENDERING_FUNCTIONS
        self.unsafe_rendering_functions = UNSAFE_RENDERING_FUNCTIONS
        
    def check(self, node_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if LLM output is passed to rendering functions without sanitization."""
        context = context or {}
        
        # This rule expects an AST call node or a dictionary of LLM output variables
        if isinstance(node_info, ast.Call):
            node = node_info
            llm_output_vars = context.get("llm_output_vars", set())
            
            # Check if this is a call to a rendering function
            func_name = self._get_full_function_name(node)
            
            if any(unsafe in func_name for unsafe in self.unsafe_rendering_functions):
                # Check if any of the arguments are LLM outputs
                for i, arg in enumerate(node.args):
                    if isinstance(arg, ast.Name) and arg.id in llm_output_vars:
                        # Get source code context and code snippet if available
                        source_code = context.get("code", "")
                        code_snippet = None
                        
                        if source_code and hasattr(node, 'lineno'):
                            # Get up to 3 lines of context around the line of code
                            lines = source_code.split('\n')
                            start_line = max(0, node.lineno - 2)
                            end_line = min(len(lines), node.lineno + 1)
                            code_snippet = '\n'.join(lines[start_line:end_line])
                        
                        # Check if this argument has been sanitized
                        sanitized_vars = context.get("sanitized_vars", set())
                        if arg.id in sanitized_vars:
                            # Skip if this variable has been sanitized
                            continue
                        
                        # Create detailed context information
                        issue_context = {
                            "variable": arg.id, 
                            "function": func_name,
                            "arg_position": i,
                            "code_snippet": code_snippet
                        }
                        
                        # If we have variable definition information, include it
                        var_defs = context.get("variable_definitions", {})
                        if arg.id in var_defs:
                            issue_context["variable_definition"] = {
                                "line": var_defs[arg.id].get("line", 0),
                                "source": var_defs[arg.id].get("source", "unknown")
                            }
                            
                        return Issue(
                            rule_id=self.rule_id,
                            message=f"LLM output variable '{arg.id}' is passed to rendering function '{func_name}' without sanitization",
                            location=self._get_location(node),
                            severity=self.severity,
                            fix_suggestion="Sanitize LLM outputs before passing to rendering functions to prevent XSS. Use libraries like bleach or html.escape to sanitize HTML or implement proper input validation.",
                            context=issue_context,
                            tags=self.tags
                        )
                
                # Check keyword arguments too
                for kw in node.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id in llm_output_vars:
                        # Get source code context and code snippet if available
                        source_code = context.get("code", "")
                        code_snippet = None
                        
                        if source_code and hasattr(node, 'lineno'):
                            # Get up to 3 lines of context around the line of code
                            lines = source_code.split('\n')
                            start_line = max(0, node.lineno - 2)
                            end_line = min(len(lines), node.lineno + 1)
                            code_snippet = '\n'.join(lines[start_line:end_line])
                        
                        # Check if this argument has been sanitized
                        sanitized_vars = context.get("sanitized_vars", set())
                        if kw.value.id in sanitized_vars:
                            # Skip if this variable has been sanitized
                            continue
                        
                        # Create detailed context information
                        issue_context = {
                            "variable": kw.value.id, 
                            "function": func_name,
                            "argument": kw.arg,
                            "code_snippet": code_snippet
                        }
                        
                        # If we have variable definition information, include it
                        var_defs = context.get("variable_definitions", {})
                        if kw.value.id in var_defs:
                            issue_context["variable_definition"] = {
                                "line": var_defs[kw.value.id].get("line", 0),
                                "source": var_defs[kw.value.id].get("source", "unknown")
                            }
                            
                        return Issue(
                            rule_id=self.rule_id,
                            message=f"LLM output variable '{kw.value.id}' is passed to rendering function '{func_name}' as keyword argument '{kw.arg}' without sanitization",
                            location=self._get_location(node),
                            severity=self.severity,
                            fix_suggestion="Sanitize LLM outputs before passing to rendering functions to prevent XSS. Use libraries like bleach or html.escape to sanitize HTML or implement proper input validation.",
                            context=issue_context,
                            tags=self.tags
                        )
        
        return None
        
    def _get_full_function_name(self, node: ast.Call) -> str:
        """Get the full function name including module/class path."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return ".".join(get_attribute_chain(node.func))
        return ""
    
    def _get_location(self, node: ast.AST) -> Dict[str, Any]:
        """Get the location information for a node."""
        return {
            "line": getattr(node, "lineno", 0),
            "col": getattr(node, "col_offset", 0),
            "end_line": getattr(node, "end_lineno", 0),
            "end_col": getattr(node, "end_col_offset", 0)
        }