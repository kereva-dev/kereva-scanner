"""
Rule for detecting system instructions placed in user messages instead of system prompts.
"""
import ast
import os
import re
from typing import Optional, Dict, Any, List, Set

from rules.base_rule import BaseRule
from core.issue import Issue

class MisplacedSystemInstructionRule(BaseRule):
    """
    Rule that checks if system instructions are misplaced in user messages.
    
    This rule looks for system-like instructions (persona guidance, formatting instructions,
    behavior constraints) that are placed in user messages instead of system messages.
    """
    
    def __init__(self):
        super().__init__(
            rule_id="misplaced-system-instruction",
            description="System instructions should be in system prompts, not user messages",
            severity="medium",
            tags=["prompt-engineering", "best-practice", "security"]
        )
        self.suggestion = "Move system instructions to a dedicated system prompt with role='system' or role='developer'"
        
        # Patterns that indicate system instructions
        self.system_instruction_patterns = [
            r"(?i)you (are|should be|will be|act as) (a|an) [a-zA-Z\s]+ assistant",
            r"(?i)act as (a|an) [a-zA-Z\s]+",
            r"(?i)you (are|will be|should) (a|an) [a-zA-Z\s]+",
            r"(?i)you (should|must|will) (never|always|only)",
            r"(?i)follow these instructions",
            r"(?i)format your (response|output|reply) (as|using|in) [a-zA-Z\s]+",
            r"(?i)respond (in|using|with) [a-zA-Z\s]+ format",
            r"(?i)(never|always|don\'t) (generate|provide|include|use)",
            r"(?i)your (task|job|role) is to",
            r"(?i)use this format",
            r"(?i)\s*format:\s*",
            r"(?i)output (should|must) be (in|formatted as)",
            r"(?i)answer in (the style|the format|a way) (of|that)",
            r"(?i)please ensure that (you|your|all)"
        ]
        
        # Patterns that are typically ok in user messages
        self.normal_user_patterns = [
            r"(?i)what (is|are)",
            r"(?i)how (do|can|would|should) (i|we|you)",
            r"(?i)can you help me",
            r"(?i)tell me about",
            r"(?i)explain",
            r"(?i)why (is|are|does)",
            r"(?i)when (is|are|should)",
            r"(?i)where (is|are|can)",
            r"(?i)(who|what|where|when|why|how)",
            r"(?i)could you"
        ]
        
    def check(self, node: Any, context: Optional[Dict[str, Any]] = None) -> Optional[Issue]:
        """
        Check if system instructions are placed in user messages.
        
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
        """Check an AST Call node for misplaced system instructions."""
        # Look for messages parameter with a list value
        for kw in node.keywords:
            if kw.arg == "messages" and isinstance(kw.value, ast.List):
                # Check each message in the list
                for msg_index, msg in enumerate(kw.value.elts):
                    if not isinstance(msg, ast.Dict):
                        continue
                        
                    # Look for role="user" messages
                    role_value = None
                    content_value = None
                    
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
                                
                        elif key_str == "content" and i < len(msg.values):
                            content_node = msg.values[i]
                            
                            # Extract content string
                            if isinstance(content_node, ast.Str):
                                content_value = content_node.s
                            elif hasattr(ast, 'Constant') and isinstance(content_node, ast.Constant):
                                content_value = content_node.value if isinstance(content_node.value, str) else None
                                
                    # If this is a user message, check for system instructions
                    if role_value == "user" and content_value:
                        system_instructions = self._detect_system_instructions(content_value)
                        if system_instructions:
                            # Create an issue for the misplaced system instructions
                            location = getattr(node, "lineno", 0)
                            function_name = self._get_function_name(node)
                            
                            return Issue(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                message=f"System instructions found in user message: {system_instructions[0][:50]}...",
                                location={"line": location, "file": context.get("file_name", "")},
                                fix_suggestion=self.suggestion,
                                context={
                                    "function_call": function_name,
                                    "message_index": msg_index,
                                    "system_instructions": system_instructions
                                },
                                tags=self.tags
                            )
                    
        return None
    
    def _check_messages_dict(self, node: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check a messages dictionary for misplaced system instructions."""
        messages = node.get("messages", [])
        
        if os.environ.get('DEBUG') == "1":
            print(f"MisplacedSystemInstructionRule checking messages: {messages}")
        
        for i, msg in enumerate(messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                # Handle non-string content (like AST nodes)
                if not isinstance(content, str):
                    if os.environ.get('DEBUG') == "1":
                        print(f"  - Content is not a string: {type(content)}")
                        
                    # If it's an ast.Constant node, try to get the string value
                    if hasattr(ast, 'Constant') and isinstance(content, ast.Constant):
                        if isinstance(content.value, str):
                            content = content.value
                            if os.environ.get('DEBUG') == "1":
                                print(f"  - Extracted string from Constant: {content[:50]}...")
                        else:
                            continue
                    # If it has a __str__ method, use it
                    elif hasattr(content, "__str__"):
                        content = str(content)
                        if os.environ.get('DEBUG') == "1":
                            print(f"  - Converted to string: {content[:50]}...")
                    else:
                        continue
                
                if os.environ.get('DEBUG') == "1":
                    print(f"  - Checking user message: {content[:50]}...")
                
                # Check directly for system instruction patterns first
                # This is more reliable than the complex paragraph analysis for simple cases
                for pattern in self.system_instruction_patterns:
                    match = re.search(pattern, content)
                    if match:
                        matched_text = match.group(0)
                        if os.environ.get('DEBUG') == "1":
                            print(f"  - Direct match found for pattern: {pattern}")
                            print(f"  - Matched text: {matched_text}")
                        
                        # Create a system instruction entry
                        context_paragraph = self._get_context_paragraph(content, matched_text)
                        system_instructions = [context_paragraph]
                        
                        return Issue(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"System instructions found in user message: {matched_text[:50]}...",
                            location={"line": node.get("line", 0), "file": context.get("file_name", "")},
                            fix_suggestion=self.suggestion,
                            context={
                                "message_index": i,
                                "system_instructions": system_instructions
                            },
                            tags=self.tags
                        )
                
                # If no direct match, use the more detailed analysis
                system_instructions = self._detect_system_instructions(content)
                if system_instructions:
                    if os.environ.get('DEBUG') == "1":
                        print(f"  - Found system instructions: {system_instructions}")
                    return Issue(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"System instructions found in user message: {system_instructions[0][:50]}...",
                        location={"line": node.get("line", 0), "file": context.get("file_name", "")},
                        fix_suggestion=self.suggestion,
                        context={
                            "message_index": i,
                            "system_instructions": system_instructions
                        },
                        tags=self.tags
                    )
                elif os.environ.get('DEBUG') == "1":
                    print(f"  - No system instructions found")
                    
        return None
        
    def _get_context_paragraph(self, content: str, match_text: str) -> str:
        """Extract the paragraph containing the matched text."""
        paragraphs = content.split("\n\n")
        for paragraph in paragraphs:
            if match_text in paragraph:
                return paragraph.strip()
        # If we can't find it in paragraphs, return 100 chars around the match
        start_idx = max(0, content.find(match_text) - 50)
        end_idx = min(len(content), content.find(match_text) + len(match_text) + 50)
        return content[start_idx:end_idx].strip()
        
    def _detect_system_instructions(self, content: str) -> List[str]:
        """
        Detect system-like instructions in a string.
        
        Returns a list of identified system instruction patterns.
        """
        if not content:
            if os.environ.get('DEBUG') == "1":
                print("      - Content is empty")
            return []
            
        # Split content into paragraphs for more accurate pattern matching
        paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
        
        if os.environ.get('DEBUG') == "1":
            print(f"      - Split into {len(paragraphs)} paragraphs")
        
        # For messages that likely contain system instructions, let's first check for those patterns
        # before ruling it out as a user query
        for pattern in self.system_instruction_patterns:
            if re.search(pattern, content):
                if os.environ.get('DEBUG') == "1":
                    print(f"      - Found system instruction pattern in content: {pattern}")
                # If we found a system instruction pattern, don't skip this message
                break
        else:
            # Only if no system instruction patterns were found, check if it's a user query
            if self._is_clear_user_query(content):
                if os.environ.get('DEBUG') == "1":
                    print("      - Content looks like a clear user query, skipping")
                return []
            
        # Look for system instruction patterns in each paragraph
        system_instructions = []
        
        for i, paragraph in enumerate(paragraphs):
            if os.environ.get('DEBUG') == "1":
                print(f"      - Checking paragraph {i+1}: {paragraph[:50]}...")
                
            # Skip very short paragraphs (less than 10 chars)
            if len(paragraph) < 10:
                if os.environ.get('DEBUG') == "1":
                    print("        - Paragraph too short, skipping")
                continue
                
            # Skip if it looks like a user query
            if self._is_clear_user_query(paragraph):
                if os.environ.get('DEBUG') == "1":
                    print("        - Paragraph looks like user query, skipping")
                continue
                
            # Check for system instruction patterns
            matched_pattern = None
            for pattern in self.system_instruction_patterns:
                match = re.search(pattern, paragraph)
                if match:
                    if os.environ.get('DEBUG') == "1":
                        print(f"        - Matched pattern: {pattern}")
                        print(f"        - Match: {match.group(0)}")
                    matched_pattern = pattern
                    system_instructions.append(paragraph)
                    break
                    
            if os.environ.get('DEBUG') == "1" and not matched_pattern:
                print("        - No patterns matched")
                    
        if os.environ.get('DEBUG') == "1":
            print(f"      - Found {len(system_instructions)} system instructions")
            
        return system_instructions
        
    def _is_clear_user_query(self, text: str) -> bool:
        """Check if a text is clearly a user query (not system instructions)."""
        # Very short texts are likely user queries
        if len(text) < 20:
            if os.environ.get('DEBUG') == "1":
                print("        - Text too short, assuming user query")
            return True
            
        # Look for patterns that suggest this is a normal user query
        for pattern in self.normal_user_patterns:
            if re.search(pattern, text):
                if os.environ.get('DEBUG') == "1":
                    print(f"        - Matched user query pattern: {pattern}")
                return True
                
        if os.environ.get('DEBUG') == "1":
            print("        - No user query patterns matched")
        return False
        
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