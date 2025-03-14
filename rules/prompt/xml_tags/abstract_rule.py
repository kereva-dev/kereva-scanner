import ast
import os
import re
from typing import Optional, Dict, Any, List, Set
from rules.base_rule import BaseRule
from core.issue import Issue


class AbstractXMLTagRule(BaseRule):
    """Base rule for checking if variables are enclosed in XML tags.
    
    This abstract implementation provides common functionality for all XML tag rules,
    including basic XML pattern matching and issue creation.
    """
    
    def __init__(self, rule_id: str, description: str, severity: str = "medium"):
        super().__init__(
            rule_id=rule_id,
            description=description,
            severity=severity
        )
        self.suggestion = "Use XML tags around variables to better control variable placement: '<variable>{variable}</variable>'"
        
        # Common pattern matching for XML tags
        self.template_pattern = re.compile(r'\{([^{}]+)\}')  # Match {variable}
        self.xml_pattern = re.compile(r'<([a-zA-Z0-9_-]+)>.*?</\1>')  # Match <tag>...</tag>
        
        # Common XML tag patterns to check
        self.common_xml_patterns = [
            "<user_input>{}</user_input>",
            "<input>{}</input>",
            "<user>{}</user>",
            "<query>{}</query>",
            "<question>{}</question>"
        ]
    
    def check(self, node_or_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if variables are properly enclosed in XML tags.
        
        This method dispatches to the appropriate implementation based on input type.
        """
        context = context or {}
        
        # Handle prompt content dictionaries
        if isinstance(node_or_info, dict) and 'content' in node_or_info:
            return self._check_prompt_content(node_or_info, context)
        
        # Handle AST nodes
        elif isinstance(node_or_info, ast.AST):
            return self._check_ast_node(node_or_info, context)
        
        # Handle unknown input types
        else:
            print(f"{self.__class__.__name__}: Unsupported input type: {type(node_or_info)}")
            return None
    
    def _check_prompt_content(self, node_info: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check extracted prompt content for XML tag issues.
        
        To be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _check_prompt_content")
    
    def _check_ast_node(self, node: ast.AST, context: Dict[str, Any]) -> Optional[Issue]:
        """Check an AST node directly for XML tag issues.
        
        To be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _check_ast_node")
    
    def _create_issue(self, node, context, message=None, unwrapped_vars=None, custom_message=None, additional_context=None):
        """Create an issue for this rule violation."""
        if custom_message:
            message = custom_message
        elif message is None:
            message = self.description
            
        if unwrapped_vars:
            if isinstance(unwrapped_vars, (list, set)):
                vars_str = ", ".join(unwrapped_vars)
                message += f" (detected variables: {vars_str})"
                
                # Process variable information for the message
                var_info = []
                
                # Include variable definitions if available
                if additional_context and "variable_definitions" in additional_context:
                    var_defs = additional_context["variable_definitions"]
                    for var, line in var_defs.items():
                        if line > 0:
                            var_info.append(f"{var} (defined at line {line})")
                        else:
                            var_info.append(var)
                
                # Include specific locations of variables in content if available
                if additional_context and "variable_locations" in additional_context:
                    var_locs = additional_context["variable_locations"]
                    for var, line in var_locs.items():
                        # Only add if not already in var_info
                        if not any(info.startswith(var) for info in var_info):
                            if line > 0:
                                var_info.append(f"{var} (found at line {line})")
                            else:
                                var_info.append(var)
                
                # Add variable info to message
                if var_info:
                    message += f"\nVariable details: {', '.join(var_info)}"
                
                # If we have API call info, include it
                if additional_context and "api_call" in additional_context:
                    message += f"\nAPI call: {additional_context['api_call']}"
            
        issue_context = {}
        if additional_context:
            issue_context.update(additional_context)
        
        if hasattr(node, 'lineno'):
            code_snippet = context.get("code", "").split("\n")[node.lineno-1:node.lineno+2]
            issue_context["code_snippet"] = "\n".join(code_snippet) if code_snippet else None
            
        return Issue(
            rule_id=self.rule_id,
            message=message,
            location={
                "line": getattr(node, 'lineno', 0),
                "column": getattr(node, 'col_offset', 0),
                "file": context.get("file_name", "<unknown>")
            },
            severity=self.severity,
            fix_suggestion=self.suggestion,
            context=issue_context if issue_context else None
        )
    
    def _is_variable_wrapped_in_xml(self, content, variable: str) -> bool:
        """Check if a variable is properly wrapped in XML tags."""
        # Skip non-string content
        if not isinstance(content, str):
            return True  # Default to true for non-string content
            
        var_pattern = f"{{{variable}}}"
        
        # Debug output
        if "DEBUG" in os.environ:
            print(f"Checking if '{variable}' is wrapped in XML tags")
            print(f"  Content: '{content}'")
            print(f"  Pattern: '{var_pattern}'")
        
        # Check if the content is essentially just the variable (entire prompt is just the variable)
        content_stripped = content.strip()
        if content_stripped == var_pattern:
            if "DEBUG" in os.environ:
                print(f"  SKIPPING - Content is exactly the variable")
            return True  # Consider single-variable prompts as properly wrapped
            
        # Check if the content is mostly just the variable with maybe some whitespace
        # This handles cases like f"  {prompt}  " or f"\n{prompt}\n"
        if self._is_content_mostly_variable(content_stripped, var_pattern):
            if "DEBUG" in os.environ:
                print(f"  SKIPPING - Content is mostly just the variable")
            return True
        
        # Generate XML patterns for this variable
        xml_patterns = [pattern.format(var_pattern) for pattern in self.common_xml_patterns]
        xml_patterns.append(f"<[^>]+>{var_pattern}</[^>]+>")  # Generic pattern
        
        # Check if any of the patterns match
        wrapped = any(re.search(pattern, content) for pattern in xml_patterns)
        
        if "DEBUG" in os.environ:
            print(f"  Result: {'Wrapped in XML' if wrapped else 'NOT wrapped in XML'}")
            
        return wrapped
        
    def _is_content_mostly_variable(self, content: str, var_pattern: str) -> bool:
        """Check if the content is mostly just the variable pattern with minimal other content."""
        # Remove the variable pattern
        remainder = content.replace(var_pattern, "")
        # If what's left is just whitespace or very minimal content
        remainder_stripped = remainder.strip()
        
        # If nothing remains or just punctuation/minimal formatting
        if not remainder_stripped or (
            len(remainder_stripped) <= 2 and 
            all(c in ",.!?:;" for c in remainder_stripped)
        ):
            return True
            
        # Another approach: if the variable pattern is >90% of the content length
        if len(var_pattern) / len(content) > 0.9:
            return True
            
        return False
    
    def _extract_template_variables(self, content) -> List[str]:
        """Extract template variables from content."""
        # Skip non-string content
        if not isinstance(content, str):
            return []
            
        return self.template_pattern.findall(content)