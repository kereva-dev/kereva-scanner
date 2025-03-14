import ast
import os
import re
from typing import Optional, Dict, Any, List, Set, Tuple
from rules.prompt.xml_tags.abstract_rule import AbstractXMLTagRule
from core.issue import Issue


class ListProtectionXMLRule(AbstractXMLTagRule):
    """Rule to check if lists in prompts are properly protected with XML tags.
    
    This rule specifically focuses on detecting when lists of data
    (like comments, examples, etc.) are not properly enclosed in XML tags,
    which can lead to prompt injection vulnerabilities.
    """
    
    def __init__(self):
        super().__init__(
            rule_id="prompt-list-xml-protection",
            description="Lists in prompts should be protected with XML tags",
            severity="high"
        )
        self.suggestion = "Wrap lists in container tags like <list>...</list> or wrap individual items in tags like <item>...</item>"
        
        # XML tag patterns for container tags
        self.list_container_tags = [
            "list", "items", "comments", "entries", "examples", "data", "records"
        ]
        
        # XML tag patterns for individual list items
        self.list_item_tags = [
            "item", "entry", "comment", "example", "record", "element", "data"
        ]
    
    def check(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Optional[Issue]:
        """Check if list variables in prompt are properly protected with XML tags."""
        context = context or {}
        file_name = context.get("file_name", "<unknown>")
        
        # First, check if this is prompt content with XML tag information
        if isinstance(data, dict) and 'list_var' in data and 'prompt_var' in data:
            # Extract list protection information from the data
            list_var = data.get("list_var")
            prompt_var = data.get("prompt_var")
            list_wrapped_in_xml = data.get("list_wrapped_in_xml", False)
            list_items_wrapped_in_xml = data.get("list_items_wrapped_in_xml", False)
            node = data.get("node")
            
            # If the list is protected with XML tags, no issue to report
            if list_wrapped_in_xml or list_items_wrapped_in_xml:
                return None
            
            # Otherwise, create an issue for the unprotected list
            line_number = getattr(node, 'lineno', 0)
            message = f"List variable '{list_var}' is added to prompt '{prompt_var}' without XML tag protection, which risks prompt injection."
            
            return Issue(
                rule_id=self.rule_id,
                message=message,
                location={
                    "line": line_number,
                    "column": getattr(node, 'col_offset', 0),
                    "file": file_name
                },
                severity=self.severity,
                fix_suggestion=self.suggestion,
                context={
                    "list_var": list_var,
                    "prompt_var": prompt_var
                }
            )
        
        # Next, check if this is an AST node with a loop that manipulates prompt content
        elif isinstance(data, dict) and 'ast_node' in data and 'loop_var' in data and 'loop_target' in data:
            # Extract loop information from the data
            ast_node = data.get("ast_node")
            loop_var = data.get("loop_var")
            loop_target = data.get("loop_target")
            target_vars = data.get("target_vars", [])
            
            # Check if the loop is working with prompt-related variables
            prompt_vars = [var for var in target_vars if self._is_prompt_variable(var)]
            if not prompt_vars:
                return None
            
            # Check if the loop items are wrapped in XML tags
            list_wrapped, items_wrapped = self._check_loop_xml_protection(ast_node, loop_var, prompt_vars[0])
            
            # If the list or items are protected with XML tags, no issue to report
            if list_wrapped or items_wrapped:
                return None
            
            # Otherwise, create an issue for the unprotected list
            line_number = getattr(ast_node, 'lineno', 0)
            message = f"Loop iterating over '{loop_target}' adds items to prompt without XML tag protection, which risks prompt injection."
            
            return Issue(
                rule_id=self.rule_id,
                message=message,
                location={
                    "line": line_number,
                    "column": getattr(ast_node, 'col_offset', 0),
                    "file": file_name
                },
                severity=self.severity,
                fix_suggestion=self.suggestion,
                context={
                    "loop_var": loop_var,
                    "loop_target": loop_target,
                    "target_vars": target_vars
                }
            )
        
        return None
    
    def _is_prompt_variable(self, var_name: str) -> bool:
        """Check if a variable name looks like it might contain a prompt."""
        prompt_related = ['prompt', 'query', 'message', 'instruction', 'system', 'request', 
                         'template', 'context', 'conversation']
        return any(term in var_name.lower() for term in prompt_related)
    
    def _check_loop_xml_protection(self, loop_node, loop_var, prompt_var) -> Tuple[bool, bool]:
        """Check if a loop adds XML tags around list items."""
        # Default to not wrapped
        list_wrapped = False
        items_wrapped = False
        
        # Check for patterns in the loop body that would indicate XML tag protection
        for stmt in loop_node.body:
            # Look for augmented assignments that add XML tags
            if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
                # Check the right side for XML tags
                if isinstance(stmt.value, ast.JoinedStr):  # f-string
                    # Check for item tag patterns in f-string
                    for tag in self.list_item_tags:
                        open_tag = f"<{tag}>"
                        close_tag = f"</{tag}>"
                        f_string_content = self._extract_fstring_content(stmt.value)
                        if open_tag in f_string_content and close_tag in f_string_content:
                            items_wrapped = True
                            break
                
                # Check for string literals
                elif isinstance(stmt.value, ast.Str) or (hasattr(ast, 'Constant') and 
                                                      isinstance(stmt.value, ast.Constant) and 
                                                      isinstance(getattr(stmt.value, 'value', None), str)):
                    content = stmt.value.s if hasattr(stmt.value, 's') else stmt.value.value
                    
                    # Check for item tags in the string
                    for tag in self.list_item_tags:
                        open_tag = f"<{tag}>"
                        close_tag = f"</{tag}>"
                        if open_tag in content and close_tag in content:
                            items_wrapped = True
                            break
        
        # Check if the container variable has opening XML tags
        # This would be detected by looking at assignments before the loop
        # and augmented assignments after the loop
        
        return list_wrapped, items_wrapped
    
    def _extract_fstring_content(self, joined_str_node) -> str:
        """Extract string content from an f-string node for pattern matching."""
        parts = []
        for value in joined_str_node.values:
            if isinstance(value, ast.Str) or (hasattr(ast, 'Constant') and isinstance(value, ast.Constant)):
                content = value.s if hasattr(value, 's') else value.value
                parts.append(str(content))
            elif isinstance(value, ast.FormattedValue):
                parts.append("{...}")
        
        return "".join(parts)