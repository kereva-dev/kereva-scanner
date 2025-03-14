import os
import re
from typing import Optional, Dict, Any, List, Set
from rules.prompt.xml_tags.abstract_rule import AbstractXMLTagRule
from core.issue import Issue
from core.ast_utils import analyze_term_locations, extract_line_from_content


class UnusedXMLTagsRule(AbstractXMLTagRule):
    """Rule to check if XML tags in prompts are mentioned in the prompt text.
    
    This rule ensures that when XML tags are used in prompts, they are properly
    explained or referenced in the prompt text, which is a recommended practice
    for better prompt design.
    """
    
    def __init__(self):
        super().__init__(
            rule_id="prompt-unused-xml-tags",
            description="XML tags in prompts should be referenced in the prompt text",
            severity="low"  # Low severity as it's a best practice rather than a security issue
        )
        self.suggestion = "Explain the purpose of XML tags in the prompt text. For example: 'Please wrap code examples in <code> tags.'"
    
    def _check_ast_node(self, node: Any, context: Dict[str, Any]) -> Optional[Issue]:
        """This rule doesn't scan AST nodes directly."""
        return None
    
    def _check_prompt_content(self, node_info: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check if XML tags used in prompts are mentioned in the prompt text."""
        content = node_info['content']
        base_line = node_info.get('line', 0)
        debug = os.environ.get('DEBUG') == "1"
        
        # Skip non-string content
        if not isinstance(content, str):
            return None
            
        # Extract all XML tags from the content
        xml_tags = self._extract_xml_tags(content)
        
        # If no XML tags found, no issue
        if not xml_tags:
            return None
        
        # Check if each tag is mentioned in the prompt text
        unused_tags = self._find_unused_tags(content, xml_tags)
        
        # If there are unused tags, create an issue
        if unused_tags:
            # For multiline content, try to locate the first occurrence of an unused tag
            # to provide a more accurate line number
            line_number = base_line
            code_snippet = None
            
            if "\n" in content and unused_tags:
                # Create patterns to search for the first unused tag
                first_tag = unused_tags[0]
                tag_patterns = [
                    f"<{first_tag}>",
                    f"<{first_tag} ",
                    f"</{first_tag}>"
                ]
                
                # Find locations of tag patterns in the content
                tag_locations = analyze_term_locations(content, tag_patterns, base_line)
                
                if tag_locations:
                    # Use the earliest occurrence for the line number
                    earliest_tag = min(tag_locations.items(), key=lambda x: x[1])
                    line_number = earliest_tag[1]
                    
                    if debug:
                        print(f"Found unused tag '{first_tag}' at line {line_number}")
                    
                    # Extract a code snippet for context
                    relative_line = line_number - base_line + 1  # +1 because extract_line_from_content is 1-indexed
                    code_snippet = extract_line_from_content(content, relative_line, 2)
            
            # Create a custom message that explains which XML tags need to be mentioned
            custom_message = f"XML tags used in prompt should be explained in the prompt text. Found tags not referenced in text: {', '.join(unused_tags)}"
            
            # Add code snippet context if available
            issue_context = {}
            if code_snippet:
                issue_context["code_snippet"] = code_snippet
            
            issue_context["unused_tags"] = unused_tags
            
            # Create the issue with the specific message about unused tags
            return Issue(
                rule_id=self.rule_id,
                message=custom_message,
                location={
                    "line": line_number,
                    "column": 0,
                    "file": context.get("file_name", "<unknown>")
                },
                severity=self.severity,
                fix_suggestion=self.suggestion,
                context=issue_context
            )
        
        return None
    
    def _extract_xml_tags(self, content) -> Set[str]:
        """Extract all unique XML tags from the content."""
        debug = os.environ.get('DEBUG') == "1"
        
        # Skip non-string content
        if not isinstance(content, str):
            return set()
            
        # Regex to match XML tags, capturing just the tag name (ignoring attributes)
        # This pattern matches opening and closing tags, and captures the tag name
        tag_pattern = r'<([a-zA-Z0-9_-]+)(?:\s+[^>]*)?>.*?</\1>'
        
        # Find all matches
        matches = re.findall(tag_pattern, content, re.DOTALL)
        
        if debug:
            print(f"Extracted XML tags: {matches}")
            
        # A list of special tags that don't need to be referenced in the text
        special_tags = ['user_input', 'input', 'user', 'query', 'question']
        
        # Return unique tag names, excluding special tags that don't need explanation
        result = set(tag for tag in matches if tag not in special_tags)
        
        if debug and result:
            print(f"Extracted non-special XML tags: {result}")
            
        return result
    
    def _find_unused_tags(self, content, tags: Set[str]) -> List[str]:
        """Find tags that are not mentioned in the natural language part of the prompt."""
        debug = os.environ.get('DEBUG') == "1"
        
        # Skip non-string content
        if not isinstance(content, str):
            return []
            
        if debug:
            print(f"Checking for unused tags in content: {content[:100]}...")
            print(f"Tags to check: {tags}")
            
        unused_tags = []
        
        # Remove the XML tags and their contents from the content to check the natural language parts
        content_without_tags = re.sub(r'<[^>]+>.*?</[^>]+>', '', content, flags=re.DOTALL)
        
        # Also remove the opening and closing tags without removing their content (like <tag></tag>)
        # This ensures we're checking just the natural language parts
        content_without_tags = re.sub(r'</?[^>]+>', '', content_without_tags)
        
        if debug:
            print(f"Content without tags: {content_without_tags[:100]}...")
            
        for tag in tags:
            # Skip the user_input tag since it's a special case and doesn't need to be referenced
            if tag in ['user_input', 'input', 'user', 'query', 'question']:
                continue
                
            # Check if the tag name is mentioned in the natural language part
            # We use word boundaries to ensure it's a whole word
            if not re.search(r'\b' + re.escape(tag) + r'\b', content_without_tags, re.IGNORECASE):
                unused_tags.append(tag)
                if debug:
                    print(f"Tag '{tag}' is not mentioned in the natural language part")
        
        if debug:
            print(f"Unused tags: {unused_tags}")
        
        return unused_tags