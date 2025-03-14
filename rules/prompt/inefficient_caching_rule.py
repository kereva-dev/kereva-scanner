import ast
import re
import os
from typing import Optional, Dict, Any, List, Tuple
from rules.base_rule import BaseRule
from core.issue import Issue
from core.ast_utils import analyze_term_locations, extract_line_from_content


class InefficientCachingRule(BaseRule):
    """Rule to check if prompts are structured efficiently for caching.
    
    This rule ensures that user inputs (questions, queries) are placed at the end of the prompt
    rather than at the beginning, which allows LLM platforms to cache the consistent part of the
    prompt and improve performance.
    """
    
    def __init__(self, min_prompt_length: int = 200):
        super().__init__(
            rule_id="prompt-inefficient-caching",
            description="Prompt structure is inefficient for LLM caching",
            severity="low"  # Performance optimization, not a security issue
        )
        # Minimum prompt length to trigger this rule (in characters)
        self.min_prompt_length = min_prompt_length
    
    def check(self, node_or_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if prompt structure is efficient for caching.
        
        This method checks if user inputs are positioned toward the end of the prompt
        rather than at the beginning, which improves caching efficiency.
        """
        context = context or {}
        
        # Two ways to check:
        # 1. If we have an AST node (direct scanning)
        if isinstance(node_or_info, ast.AST):
            return self._check_ast_node(node_or_info, context)
        
        # 2. If we have extracted prompt content (from PromptExtractor)
        elif isinstance(node_or_info, dict) and 'content' in node_or_info:
            return self._check_prompt_content(node_or_info, context)
            
        return None
    
    def _check_ast_node(self, node: ast.AST, context: Dict[str, Any]) -> Optional[Issue]:
        """Check an AST node for inefficient prompt caching patterns."""
        # Only perform this analysis on f-strings that are assigned to variables
        if not isinstance(node, ast.Assign):
            return None
            
        # Check if we're assigning to a variable named "prompt" or similar
        if not (len(node.targets) == 1 and 
                isinstance(node.targets[0], ast.Name) and 
                self._is_prompt_variable(node.targets[0].id)):
            return None
            
        # Debug information
        var_name = node.targets[0].id
        debug = os.environ.get('DEBUG') == "1"
        
        if debug:
            print(f"Checking variable for caching efficiency: {var_name}")
            
        # Check if the value is an f-string (JoinedStr) or other relevant string type
        if isinstance(node.value, ast.JoinedStr):
            if debug: print(f"  - Found f-string assignment")
        elif isinstance(node.value, ast.Str) or (hasattr(ast, 'Constant') and isinstance(node.value, ast.Constant)):
            if debug: print(f"  - Found string literal assignment")
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'format':
            if debug: print(f"  - Found string.format() assignment")
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'strip':
            if debug: print(f"  - Found string.strip() assignment")
        else:
            if debug: print(f"  - Not a recognized string type: {type(node.value).__name__}")
            return None
            
        # Extract the full string content and analyze it
        prompt_str = self._extract_string_from_node(node.value)
        
        # If we couldn't extract a meaningful string, skip
        if not prompt_str:
            if debug: print(f"  - Couldn't extract string content")
            return None
            
        if debug:
            print(f"  - Extracted string length: {len(prompt_str)}")
            print(f"  - Min length threshold: {self.min_prompt_length}")
            
        if len(prompt_str) < self.min_prompt_length:
            if debug: print(f"  - String too short to trigger rule")
            return None
            
        # Get the base line number for this multiline string
        base_line = getattr(node, 'lineno', 0)
        
        # Use common patterns that indicate user input
        user_input_patterns = [
            r'user(?:\s*input|\s*query|\s*question):\s*',
            r'query:\s*',
            r'question:\s*',
            r'<user_input>',
            r'<user>',
            r'<query>',
            r'<question>',
            r'\{user_input\}',
            r'\{query\}',
            r'\{question\}',
            r'\{\.\.\.\}',  # Placeholder we use for f-string values
            r'User query:',
            r'User question:',
            r'User input:'
        ]
            
        # Get the relative position for the standard check
        user_input_pos = self._find_user_input_position(prompt_str, debug)
            
        # If there's user input early in the prompt (first 30%), flag as inefficient
        if user_input_pos is not None and user_input_pos < 0.3:
            # Find the specific line where the issue occurs in multiline strings
            if "\n" in prompt_str:
                # Find line numbers of patterns in the content
                pattern_locations = analyze_term_locations(prompt_str, user_input_patterns, base_line, True)
                
                if debug:
                    print(f"  - Base line number: {base_line}")
                    print(f"  - Pattern locations: {pattern_locations}")
                
                # Use accurate line for issue if we found a pattern
                if pattern_locations:
                    earliest_pattern = min(pattern_locations.items(), key=lambda x: x[1])
                    earliest_pattern_line = earliest_pattern[1]
                    
                    if debug:
                        print(f"  - Earliest pattern: {earliest_pattern[0]} at line {earliest_pattern_line}")
                    
                    # Get a code snippet around the issue location
                    lines = prompt_str.split('\n')
                    
                    # For multiline string literals in f-strings, we need to add 1 to the line number
                    # since the first line with the """ doesn't contain the actual pattern
                    if earliest_pattern_line == base_line and lines[0].strip() == "":
                        earliest_pattern_line += 1
                        if debug:
                            print(f"  - Adjusting for multiline string: new line {earliest_pattern_line}")
                    
                    offset = earliest_pattern_line - base_line
                    if 0 <= offset < len(lines):
                        if debug:
                            print(f"  - Content line with issue: {lines[offset]}")
                        # Get up to 3 lines of context
                        start = max(0, offset - 1)
                        end = min(len(lines), offset + 2)
                        code_snippet = '\n'.join(lines[start:end])
                        
                        # Create a mock node with the accurate line number
                        class MockNode:
                            def __init__(self, line):
                                self.lineno = line
                                self.col_offset = 0
                                
                        mock_node = MockNode(earliest_pattern_line)
                        return self._create_issue(mock_node, context, 
                                    additional_context={"code_snippet": code_snippet,
                                                      "input_position": f"{user_input_pos:.2%} into the prompt"})
                
            # Default to the standard issue creation with the original node
            if debug: print(f"  - User input is in the first 30% of prompt (inefficient)")
            return self._create_issue(node, context, 
                          additional_context={"input_position": f"{user_input_pos:.2%} into the prompt"})
        else:
            if debug: print(f"  - No user input position found, or it's not at the beginning")
            
        return None
    
    def _check_prompt_content(self, node_info: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check extracted prompt content for inefficient caching patterns."""
        content = node_info['content']
        base_line = node_info.get('line', 0)
        
        # Skip non-string content
        if not isinstance(content, str):
            return None
            
        # Skip if prompt is too short to matter for caching
        if len(content) < self.min_prompt_length:
            return None
        
        # Use common patterns that indicate user input
        user_input_patterns = [
            r'user(?:\s*input|\s*query|\s*question):\s*',
            r'query:\s*',
            r'question:\s*',
            r'<user_input>',
            r'<user>',
            r'<query>',
            r'<question>',
            r'\{user_input\}',
            r'\{query\}',
            r'\{question\}',
            r'\{\.\.\.\}',  # Placeholder we use for f-string values
            r'User query:',
            r'User question:',
            r'User input:'
        ]
            
        # Find where these patterns appear in the content
        pattern_locations = analyze_term_locations(content, user_input_patterns, base_line, True)
        
        if not pattern_locations:
            return None  # No user input patterns found
            
        # Get the earliest user input pattern and its position
        earliest_pattern = min(pattern_locations.items(), key=lambda x: x[1])
        earliest_pattern_line = earliest_pattern[1]
        
        # Get position as a float from 0.0 to 1.0
        user_input_pos = self._find_user_input_position(content)
        
        # If there's user input early in the prompt (first 30%), flag as inefficient
        if user_input_pos is not None and user_input_pos < 0.3:
            # Get a code snippet around the issue location
            code_snippet = extract_line_from_content(content, earliest_pattern_line - base_line + 1, 2)
            
            # Create a mock node with accurate line number for issue reporting
            class MockNode:
                def __init__(self, line):
                    self.lineno = line
                    self.col_offset = 0
                    
            mock_node = MockNode(earliest_pattern_line)
            
            return self._create_issue(mock_node, context, 
                               additional_context={"code_snippet": code_snippet,
                                                  "input_position": f"{user_input_pos:.2%} into the prompt"})
        
        return None
    
    def _extract_string_from_node(self, node) -> Optional[str]:
        """Extract a string representation from an AST node."""
        if isinstance(node, ast.Str):
            return node.s
        elif hasattr(ast, 'Constant') and isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.JoinedStr):
            # Simple extraction of f-string parts
            parts = []
            for value in node.values:
                if isinstance(value, ast.Str) or (hasattr(ast, 'Constant') and isinstance(value, ast.Constant)):
                    parts.append(value.s if hasattr(value, 's') else value.value)
                elif isinstance(value, ast.FormattedValue):
                    parts.append("{...}")  # Placeholder for formatted value
            return ''.join(parts)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # Handle method calls like strip() and format()
            if node.func.attr == 'strip':
                return self._extract_string_from_node(node.func.value)
            elif node.func.attr == 'format':
                return self._extract_string_from_node(node.func.value)
        return None
    
    def _find_user_input_position(self, content: str, debug: bool = False) -> Optional[float]:
        """Find the relative position (0.0 to 1.0) of user input in the prompt.
        
        Args:
            content: The prompt content to check
            debug: Whether to print debug information
            
        Returns:
            Relative position (0.0 to 1.0) of user input or None if not found
        """
        # Look for common patterns that indicate user input
        patterns = [
            r'user(?:\s*input|\s*query|\s*question):\s*',
            r'query:\s*',
            r'question:\s*',
            r'<user_input>',
            r'<user>',
            r'<query>',
            r'<question>',
            r'\{user_input\}',
            r'\{query\}',
            r'\{question\}',
            r'\{\.\.\.\}',  # Placeholder we use for f-string values
            r'User query:',
            r'User question:',
            r'User input:'
        ]
        
        # Find the earliest occurrence of any pattern
        earliest_pos = None
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                pos = match.start() / len(content)  # Relative position (0.0 to 1.0)
                if debug:
                    print(f"    - Found pattern '{pattern}' at position {pos:.2f}")
                if earliest_pos is None or pos < earliest_pos:
                    earliest_pos = pos
        
        return earliest_pos
    
    def _is_prompt_variable(self, var_name: str) -> bool:
        """Check if a variable name looks like it might contain a prompt."""
        prompt_related = ['prompt', 'query', 'message', 'instruction', 'system', 'user']
        return any(term in var_name.lower() for term in prompt_related)
    
    def _create_issue(self, node, context, additional_context=None):
        """Create an issue for this rule violation."""
        message = "Prompt structure is inefficient for caching. User inputs should be at the end of the prompt, not the beginning."
        
        # Add more details if available
        if additional_context and "input_position" in additional_context:
            message += f"\nUser input found {additional_context['input_position']}"
        
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print(f"  - Creating issue at line {getattr(node, 'lineno', 0)}")
        
        # Build the context dictionary    
        issue_context = {}
        if additional_context:
            issue_context.update(additional_context)
            
        issue = Issue(
            rule_id=self.rule_id,
            message=message,
            location={
                "line": getattr(node, 'lineno', 0),
                "column": getattr(node, 'col_offset', 0),
                "file": context.get("file_name", "<unknown>")
            },
            severity=self.severity,
            fix_suggestion="Restructure the prompt to keep consistent content (system instructions, context) at the beginning and place user inputs toward the end for better caching",
            context=issue_context
        )
        
        if debug:
            print(f"  - Created issue: {issue}")
        return issue