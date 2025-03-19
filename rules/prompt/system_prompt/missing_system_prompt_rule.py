"""
Rule for detecting LLM API calls that don't use a system prompt.
"""
import ast
from typing import Optional, Dict, Any, List

from rules.base_rule import BaseRule
from core.issue import Issue

class MissingSystemPromptRule(BaseRule):
    """
    Rule that checks if LLM API calls include a system prompt.
    
    This rule verifies that when using chat-based LLM APIs, a system prompt
    (role="system" or role="developer") is provided in the messages array.
    """
    
    def __init__(self):
        super().__init__(
            rule_id="missing-system-prompt",
            description="LLM API calls should include a system prompt for better control and safety",
            severity="medium",
            tags=["prompt-engineering", "best-practice", "security"]
        )
        self.suggestion = "Add a system prompt with role='system' or role='developer' to guide the model's behavior"
        
    def check(self, node: Any, context: Optional[Dict[str, Any]] = None) -> Optional[Issue]:
        """
        Check if an LLM API call is missing a system prompt.
        
        Args:
            node: The node to check, either an AST node or a dictionary with message data
            context: Optional context information
            
        Returns:
            An Issue if the rule is violated, None otherwise
        """
        context = context or {}
        
        # Handle different input types
        if isinstance(node, ast.Call):
            return self._check_ast_call(node, context)
        elif isinstance(node, dict) and "messages" in node:
            return self._check_messages_dict(node, context)
            
        return None
    
    def _check_ast_call(self, node: ast.Call, context: Dict[str, Any]) -> Optional[Issue]:
        """Check an AST Call node for missing system prompts."""
        # Look for messages parameter with a list value
        for kw in node.keywords:
            if kw.arg == "messages" and isinstance(kw.value, ast.List):
                # Check if any message in the list has role="system" or role="developer"
                has_system_prompt = False
                
                for msg in kw.value.elts:
                    if not isinstance(msg, ast.Dict):
                        continue
                        
                    # Look for role="system" or role="developer" in the message dictionary
                    role_value = None
                    
                    for i, key in enumerate(msg.keys):
                        # Extract key string
                        key_str = None
                        if isinstance(key, ast.Str):
                            key_str = key.s
                        elif hasattr(ast, 'Constant') and isinstance(key, ast.Constant):
                            key_str = key.value if isinstance(key.value, str) else None
                            
                        if key_str == "role" and i < len(msg.values):
                            value = msg.values[i]
                            
                            # Extract value string
                            if isinstance(value, ast.Str):
                                role_value = value.s
                            elif hasattr(ast, 'Constant') and isinstance(value, ast.Constant):
                                role_value = value.value if isinstance(value.value, str) else None
                            
                            if role_value in ["system", "developer"]:
                                has_system_prompt = True
                                break
                
                if not has_system_prompt:
                    # Create an issue for the missing system prompt
                    location = getattr(node, "lineno", 0)
                    function_name = self._get_function_name(node)
                    
                    return Issue(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"LLM API call {function_name}() is missing a system prompt",
                        location={"line": location, "file": context.get("file_name", "")},
                        fix_suggestion=self.suggestion,
                        context={"function_call": function_name},
                        tags=self.tags
                    )
                    
        return None
    
    def _check_messages_dict(self, node: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check a messages dictionary for missing system prompts."""
        messages = node.get("messages", [])
        has_system_prompt = any(
            isinstance(msg, dict) and 
            msg.get("role") in ["system", "developer"]
            for msg in messages
        )
        
        if not has_system_prompt:
            return Issue(
                rule_id=self.rule_id,
                severity=self.severity,
                message="LLM API call is missing a system prompt",
                location={"line": node.get("line", 0), "file": context.get("file_name", "")},
                fix_suggestion=self.suggestion,
                context={},
                tags=self.tags
            )
            
        return None
        
    def _get_function_name(self, node: ast.Call) -> str:
        """Extract the function name from a Call node for better error reporting."""
        if isinstance(node.func, ast.Attribute):
            attr_chain = []
            current = node.func
            
            while isinstance(current, ast.Attribute):
                attr_chain.append(current.attr)
                current = current.value
                
            if isinstance(current, ast.Name):
                attr_chain.append(current.id)
                attr_chain.reverse()
                return ".".join(attr_chain)
                
        return "API call"