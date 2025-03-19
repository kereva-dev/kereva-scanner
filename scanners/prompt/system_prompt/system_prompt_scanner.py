"""
Scanner for system prompt-related issues in LLM API calls.
"""
import ast
import os
from typing import List, Optional, Dict, Any, Set

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from scanners.prompt.prompt_extractor import PromptExtractor
from core.ast_utils import get_function_name, extract_string_value, is_call_matching

from rules.prompt.system_prompt.missing_system_prompt_rule import MissingSystemPromptRule
from rules.prompt.system_prompt.misplaced_system_instruction_rule import MisplacedSystemInstructionRule


class SystemPromptScanner(BaseScanner):
    """
    Scanner for system prompt-related issues in LLM API calls.
    
    This scanner checks for:
    1. Missing system prompts in LLM API calls
    2. System instructions placed in user messages instead of system prompts
    
    It extends the prompt extraction capabilities to specifically analyze
    message objects and their role/content structure.
    """
    
    def __init__(self):
        # Initialize with system prompt rules
        rules = [
            MissingSystemPromptRule(),
            MisplacedSystemInstructionRule()
        ]
        super().__init__(rules)
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """
        Scan for system prompt-related issues in LLM API calls.
        
        Args:
            ast_node: The AST node to scan
            context: The context for the scan
            
        Returns:
            List of issues found
        """
        context = context or {}
        extractor = PromptExtractor(context)
        
        # First, apply system prompt rules directly to the AST node
        self.apply_rules(ast_node, context)
                
        # Then, extract API calls and message structures from the code
        if hasattr(ast_node, 'body'):
            # Enhanced visitor that tracks variable references
            api_call_visitor = EnhancedAPICallVisitor()
            api_call_visitor.context = context
            api_call_visitor.scanner = self
            api_call_visitor.visit(ast_node)
            
            # Get tracked message arrays from our enhanced visitor
            message_arrays = api_call_visitor.get_message_arrays()
            
            # Debug output
            if os.environ.get('DEBUG') == "1":
                print(f"SystemPromptScanner: Found {len(message_arrays)} message arrays in {context.get('file_name', 'unknown')}")
                for i, msg_array in enumerate(message_arrays):
                    print(f"  Message Array {i+1} at line {msg_array.get('line', 0)}:")
                    for j, msg in enumerate(msg_array.get('messages', [])):
                        role = msg.get('role', 'unknown')
                        content = msg.get('content', '')
                        if isinstance(content, str) and len(content) > 50:
                            content = content[:50] + "..."
                        print(f"    Message {j+1}: role={role}, content='{content}'")
            
            # Record all message arrays for comprehensive reporting
            for msg_array in message_arrays:
                self.record_scanned_element("message_arrays", {
                    "messages": msg_array.get('messages', []),
                    "line_number": msg_array.get('line', 0),
                    "api_call": msg_array.get('api_call', ''),
                    "file": context.get('file_name', 'unknown')
                })
            
            # Apply rules to all extracted message arrays
            for msg_array in message_arrays:
                for rule in self.rules:
                    if hasattr(rule, "check"):
                        issue = rule.check(msg_array, context)
                        if issue:
                            self.issues.append(issue)
                            
                            if os.environ.get('DEBUG') == "1":
                                print(f"SystemPromptScanner: Found issue with rule {rule.rule_id} at line {issue.location.get('line', 0)}")
                        
        return self.issues


class EnhancedAPICallVisitor(BaseVisitor):
    """
    Enhanced visitor for finding LLM API calls and tracking message variables.
    Adds variable tracking functionality to handle cases where the messages parameter
    is defined separately and passed as a variable.
    """
    
    def __init__(self):
        super().__init__()
        self.context = {}
        self.scanner = None
        self.message_arrays = []
        self.variable_message_arrays = {}  # Maps variable names to message arrays
        self.llm_api_calls = []  # Tracking LLM API calls
        
    def visit_Assign(self, node):
        """Track variable assignments that might be message arrays."""
        super().visit_Assign(node)
        
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            
            # Check if this is a message array assignment (a list of dicts)
            if isinstance(node.value, ast.List):
                messages = self._extract_messages_from_list(node.value)
                if messages:
                    if os.environ.get('DEBUG') == "1":
                        print(f"EnhancedAPICallVisitor: Found message array assignment to variable '{var_name}' at line {node.lineno}")
                        
                    self.variable_message_arrays[var_name] = {
                        "messages": messages,
                        "line": node.lineno
                    }
        
    def _extract_messages_from_list(self, list_node):
        """
        Extract messages from an AST List node.
        
        Args:
            list_node: An ast.List node that might contain message dictionaries
            
        Returns:
            List of message dictionaries with role and content
        """
        if not isinstance(list_node, ast.List):
            return []
            
        messages = []
        
        for item in list_node.elts:
            if isinstance(item, ast.Dict):
                message = {}
                
                # Extract keys and values from the dictionary
                for i, key_node in enumerate(item.keys):
                    if i >= len(item.values):
                        continue
                        
                    # Extract the key string
                    key_str = extract_string_value(key_node)
                    if not key_str:
                        continue
                        
                    # Extract the value based on the key
                    value_node = item.values[i]
                    
                    if key_str == "role":
                        # Extract role value
                        role_value = extract_string_value(value_node)
                        if role_value:
                            message["role"] = role_value
                            
                    elif key_str == "content":
                        # Extract content value
                        content_value = extract_string_value(value_node)
                        if content_value is not None:
                            message["content"] = content_value
                        # Handle variable references
                        elif isinstance(value_node, ast.Name):
                            var_name = value_node.id
                            if var_name in self.variables:
                                var_info = self.variables.get(var_name, {})
                                message["content"] = var_info.get("value", f"VARIABLE:{var_name}")
                            else:
                                message["content"] = f"VARIABLE:{var_name}"
                
                if message:
                    messages.append(message)
                    
        return messages
        
    def visit_Call(self, node):
        """
        Visit a function call node and check for LLM API calls.
        Enhanced to handle variable message arrays.
        """
        # Check if this is an LLM API call
        if self._is_llm_api_call(node):
            # Store the LLM API call for later analysis
            function_name = self._get_function_name(node)
            call_info = {
                "node": node,
                "function_name": function_name,
                "line": getattr(node, "lineno", 0)
            }
            self.llm_api_calls.append(call_info)
            
            # Extract messages parameter
            for kw in node.keywords:
                if kw.arg == "messages":
                    if isinstance(kw.value, ast.List):
                        # Direct list of messages
                        messages = self._extract_messages_from_list(kw.value)
                        if messages:
                            message_array = {
                                "messages": messages,
                                "line": getattr(node, "lineno", 0),
                                "api_call": function_name
                            }
                            self.message_arrays.append(message_array)
                            
                    elif isinstance(kw.value, ast.Name):
                        # Variable reference to a messages array
                        var_name = kw.value.id
                        if var_name in self.variable_message_arrays:
                            # We found a variable that contains message definitions
                            var_messages = self.variable_message_arrays[var_name]
                            message_array = {
                                "messages": var_messages["messages"],
                                "line": getattr(node, "lineno", 0),
                                "api_call": function_name,
                                "variable_name": var_name,
                                "variable_line": var_messages["line"]
                            }
                            self.message_arrays.append(message_array)
                            
                            if os.environ.get('DEBUG') == "1":
                                print(f"EnhancedAPICallVisitor: Resolved message array from variable '{var_name}' at line {getattr(node, 'lineno', 0)}")
        
        # Apply scanner rules to the call node
        if self.scanner and self._is_llm_api_call(node):
            self.scanner.apply_rules(node, self.context)
        
        # Continue visiting child nodes
        self.generic_visit(node)
        
    def _is_llm_api_call(self, node: ast.Call) -> bool:
        """Check if a node is an LLM API call."""
        # Get the function name
        function_name = self._get_function_name(node)
        
        # Check if function_name is None and return early if so
        if function_name is None:
            return False
            
        # Check for common LLM API call patterns
        llm_api_patterns = [
            "openai.ChatCompletion.create",
            "openai.chat.completions.create",
            "client.chat.completions.create",
            "client.beta.chat.completions.parse",  # Added to support the beta API in famous.py
            "anthropic.Anthropic().messages.create",
            "anthropic.messages.create",
            "client.messages.create"
        ]
        
        return any(pattern in function_name for pattern in llm_api_patterns)
    
    def _get_function_name(self, node: ast.Call) -> str:
        """Extract the function name from a Call node."""
        return get_function_name(node)
        
    def get_message_arrays(self) -> List[Dict[str, Any]]:
        """Get all detected message arrays."""
        return self.message_arrays