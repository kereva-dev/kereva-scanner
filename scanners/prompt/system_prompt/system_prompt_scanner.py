"""
Scanner for system prompt-related issues in LLM API calls.
"""
import ast
import os
from typing import List, Optional, Dict, Any

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from scanners.prompt.prompt_extractor import PromptExtractor

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
            api_call_visitor = APICallVisitor()
            api_call_visitor.context = context
            api_call_visitor.scanner = self
            api_call_visitor.visit(ast_node)
            
            # Set the context tree for the extractor to use
            extractor.context = {'tree': ast_node}
            
            # Use the prompt extractor to find messages arrays and their structure
            extractor.visit(ast_node)
            messages_arrays = extractor.extract_messages_arrays()
            
            # Debug output
            if os.environ.get('DEBUG') == "1":
                print(f"SystemPromptScanner: Found {len(messages_arrays)} message arrays in {context.get('file_name', 'unknown')}")
                for i, msg_array in enumerate(messages_arrays):
                    print(f"  Message Array {i+1} at line {msg_array.get('line', 0)}:")
                    for j, msg in enumerate(msg_array.get('messages', [])):
                        role = msg.get('role', 'unknown')
                        content = msg.get('content', '')
                        if isinstance(content, str) and len(content) > 50:
                            content = content[:50] + "..."
                        print(f"    Message {j+1}: role={role}, content='{content}'")
            
            # Record all message arrays for comprehensive reporting
            for msg_array in messages_arrays:
                self.record_scanned_element("message_arrays", {
                    "messages": msg_array.get('messages', []),
                    "line_number": msg_array.get('line', 0),
                    "api_call": msg_array.get('api_call', ''),
                    "file": context.get('file_name', 'unknown')
                })
            
            # Apply rules to all extracted message arrays
            for msg_array in messages_arrays:
                for rule in self.rules:
                    if hasattr(rule, "check"):
                        issue = rule.check(msg_array, context)
                        if issue:
                            self.issues.append(issue)
                            
                            if os.environ.get('DEBUG') == "1":
                                print(f"SystemPromptScanner: Found issue with rule {rule.rule_id} at line {issue.location.get('line', 0)}")
                        
        return self.issues


class APICallVisitor(BaseVisitor):
    """
    Visitor for finding LLM API calls and applying system prompt rules.
    """
    
    def __init__(self):
        super().__init__()
        self.context = {}
        self.scanner = None
        
    def visit_Call(self, node):
        """
        Visit a function call node and check for LLM API calls.
        """
        # Check if this is an LLM API call
        if self._is_llm_api_call(node):
            # Apply system prompt rules to the call node
            if self.scanner:
                self.scanner.apply_rules(node, self.context)
        
        # Continue visiting child nodes
        self.generic_visit(node)
        
    def _is_llm_api_call(self, node: ast.Call) -> bool:
        """Check if a node is an LLM API call."""
        # Get the function name
        function_name = self._get_function_name(node)
        
        # Check for common LLM API call patterns
        llm_api_patterns = [
            "openai.ChatCompletion.create",
            "openai.chat.completions.create",
            "client.chat.completions.create",
            "anthropic.Anthropic().messages.create",
            "anthropic.messages.create",
            "client.messages.create"
        ]
        
        return any(pattern in function_name for pattern in llm_api_patterns)
    
    def _get_function_name(self, node: ast.Call) -> str:
        """Extract the function name from a Call node."""
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
                
        return "unknown"