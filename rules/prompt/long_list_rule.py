import ast
import os
import re
from typing import Optional, Dict, Any, List, Tuple, Set
from rules.base_rule import BaseRule
from core.issue import Issue
from core.ast_utils import extract_line_from_content


class LongListRule(BaseRule):
    """Rule to detect programmatically adding long lists to prompts.
    
    LLMs can struggle with attention over long lists of items (like user comments,
    news stories, etc.) in the context window. This rule identifies code patterns
    that might lead to inserting large amounts of list data into prompts.
    """
    
    def __init__(self, warning_threshold: int = 10):
        super().__init__(
            rule_id="prompt-long-list-attention",
            description="Long list added to prompt can cause LLM attention issues",
            severity="medium",
            tags=["performance", "attention", "data-size", "prompt-engineering"]
        )
        self.warning_threshold = warning_threshold
        self.suggestion = "Consider limiting the number of items, summarizing data before sending to the LLM, or using a chunking approach to process items in smaller batches."
        
        # XML tag patterns for list protection
        self.list_container_tags = [
            "list", "items", "comments", "entries", "examples", "data"
        ]
        
        # XML tag patterns for individual list items
        self.list_item_tags = [
            "item", "entry", "comment", "example", "record", "element"
        ]
    
    def check(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Optional[Issue]:
        """
        Check if a list variable is being added to a prompt.
        
        Args:
            data: Dictionary containing information about the detected pattern
            context: Additional context information
            
        Returns:
            Issue if a violation is found, None otherwise
        """
        context = context or {}
        debug = os.environ.get('DEBUG') == "1"
        
        if not isinstance(data, dict):
            return None
            
        # Extract relevant information from the data
        node = data.get("node")
        list_var = data.get("list_var")
        prompt_var = data.get("prompt_var")
        pattern_type = data.get("pattern_type", "generic")
        list_content = data.get("list_content")
        list_wrapped_in_xml = data.get("list_wrapped_in_xml", False)
        list_items_wrapped_in_xml = data.get("list_items_wrapped_in_xml", False)
        
        if not node or not list_var:
            return None
            
        # Create appropriate message based on pattern type and XML tag protection
        message = self._create_message(list_var, prompt_var, pattern_type, 
                                     list_wrapped_in_xml, list_items_wrapped_in_xml)
        
        # Get line number and extra context for the issue
        line_number = getattr(node, 'lineno', 0)
        issue_context = {}
        
        # If we have access to the actual content of the node or prompt,
        # try to extract a meaningful code snippet
        if list_content and isinstance(list_content, str):
            if debug:
                print(f"Found list content for {list_var}, length: {len(list_content)}")
            
            # For multiline content, extract a relevant code snippet
            if "\n" in list_content:
                code_snippet = extract_line_from_content(list_content, 1, 2)
                if code_snippet:
                    issue_context["code_snippet"] = code_snippet
                    if debug:
                        print(f"Extracted code snippet: {code_snippet}")
        
        # Add information about the list length if available
        list_length = data.get("list_length")
        if list_length:
            issue_context["list_length"] = list_length
            if debug:
                print(f"List length: {list_length}")
        
        # For template patterns, provide additional info in context
        if pattern_type == "template":
            issue_context["template_type"] = data.get("template_type", "unknown")
        
        # Add XML tag information to the context
        issue_context["list_wrapped_in_xml"] = list_wrapped_in_xml
        issue_context["list_items_wrapped_in_xml"] = list_items_wrapped_in_xml
        
        # Use the default severity - don't adjust based on XML tags
        severity = self.severity
        
        # Use the standard suggestion without XML tag recommendations
        suggestion = self.suggestion
            
        # Create the issue with enhanced location and context
        return Issue(
            rule_id=self.rule_id,
            message=message,
            location={
                "line": line_number,
                "column": getattr(node, 'col_offset', 0),
                "file": context.get("file_name", "<unknown>")
            },
            severity=severity,
            fix_suggestion=suggestion,
            context=issue_context,
            tags=self.tags
        )
    
    def _create_message(self, list_var: str, prompt_var: str, pattern_type: str,
                      list_wrapped_in_xml: bool, list_items_wrapped_in_xml: bool) -> str:
        """Create an appropriate message based on pattern type."""
        # Base message about attention issues - no XML tag warnings
        if pattern_type == "template":
            return f"Potential attention issues: Template rendering with long list '{list_var}'. LLMs may struggle with attention when many items are included via templating."
        else:
            return f"Potential attention issues: Long list '{list_var}' is programmatically added to prompt '{prompt_var}'. LLMs may struggle with attention over many items."
    
    def check_list_xml_protection(self, prompt_content: str, list_items: List[str]) -> Tuple[bool, bool]:
        """
        Check if a list in a prompt is properly protected with XML tags.
        
        Args:
            prompt_content: The full prompt content
            list_items: The list items that were added to the prompt
            
        Returns:
            Tuple of (list_wrapped_in_xml, list_items_wrapped_in_xml) booleans
        """
        # Check if the list as a whole is wrapped in appropriate XML tags
        list_wrapped = self._is_list_wrapped(prompt_content, list_items)
        
        # Check if individual list items are wrapped in appropriate XML tags
        items_wrapped = self._are_list_items_wrapped(prompt_content, list_items)
        
        return list_wrapped, items_wrapped
    
    def _is_list_wrapped(self, prompt_content: str, list_items: List[str]) -> bool:
        """Check if the list as a whole is wrapped in XML tags."""
        if not isinstance(prompt_content, str) or not list_items:
            return False
        
        # Try to identify a section of the prompt that contains the list items
        list_section = self._find_list_section(prompt_content, list_items)
        if not list_section:
            return False
        
        # Check if this section is wrapped in appropriate XML tags
        for tag in self.list_container_tags:
            # Check for opening and closing tags
            open_pattern = f"<{tag}[^>]*>"
            close_pattern = f"</{tag}>"
            
            if (re.search(open_pattern, list_section, re.DOTALL) and 
                re.search(close_pattern, list_section, re.DOTALL)):
                return True
        
        return False
    
    def _are_list_items_wrapped(self, prompt_content: str, list_items: List[str]) -> bool:
        """Check if individual list items are wrapped in XML tags."""
        if not isinstance(prompt_content, str) or not list_items:
            return False
        
        # We need to find each list item in the prompt and check if it's wrapped
        wrapped_items = 0
        
        for item in list_items:
            if not item.strip():
                continue  # Skip empty items
                
            # Find the item in the prompt
            item_pos = prompt_content.find(item)
            if item_pos == -1:
                continue  # Item not found
            
            # Get some context around the item
            start = max(0, item_pos - 50)
            end = min(len(prompt_content), item_pos + len(item) + 50)
            context_text = prompt_content[start:end]
            
            # Check if the item is wrapped in any appropriate XML tags
            for tag in self.list_item_tags:
                # Look for item wrapped in tag
                pattern = f"<{tag}[^>]*>.*?{re.escape(item)}.*?</{tag}>"
                if re.search(pattern, context_text, re.DOTALL):
                    wrapped_items += 1
                    break
        
        # Consider items wrapped if at least 75% of them are wrapped
        return wrapped_items >= len(list_items) * 0.75
    
    def _find_list_section(self, prompt_content: str, list_items: List[str]) -> Optional[str]:
        """Try to identify the section of the prompt containing the list items."""
        if not list_items:
            return None
            
        # Find the first and last items in the prompt
        first_item = list_items[0]
        last_item = list_items[-1]
        
        first_pos = prompt_content.find(first_item)
        last_pos = prompt_content.rfind(last_item)
        
        if first_pos == -1 or last_pos == -1:
            return None
            
        # Get the section containing all list items with some context
        start = max(0, first_pos - 200)
        end = min(len(prompt_content), last_pos + len(last_item) + 200)
        
        return prompt_content[start:end]