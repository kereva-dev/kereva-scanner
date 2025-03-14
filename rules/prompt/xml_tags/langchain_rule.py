import ast
import re
from typing import Optional, Dict, Any, List
from rules.prompt.xml_tags.abstract_rule import AbstractXMLTagRule
from core.issue import Issue


class LangChainXMLTagRule(AbstractXMLTagRule):
    """Rule for checking proper XML tag usage in LangChain templates and prompts."""
    
    def __init__(self):
        super().__init__(
            rule_id="prompt-langchain-xml-tags",
            description="LangChain template variable not wrapped in XML tags",
            severity="medium"
        )
    
    def _check_ast_node(self, node: ast.AST, context: Dict[str, Any]) -> Optional[Issue]:
        """Check AST nodes for hub.pull() calls."""
        if isinstance(node, ast.Call):
            # Check for hub.pull() calls
            if self._is_hub_pull(node):
                prompt_id = self._extract_prompt_id(node)
                if prompt_id:
                    # We found a hub.pull() call, but can't analyze the actual prompt content
                    # since it's fetched at runtime. We'll just flag it for manual inspection.
                    return Issue(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"LangChain hub prompt '{prompt_id}' should use XML tags for variables",
                        fix_suggestion=self.suggestion,
                        context={"prompt_id": prompt_id},
                        location={"line": getattr(node, "lineno", 0), "file": context.get("file_name", "<unknown>")}
                    )
        
        # Continue to visit child nodes to find more issues
        for child in ast.iter_child_nodes(node):
            result = self._check_ast_node(child, context)
            if result:
                return result
        
        return None
    
    def _check_prompt_content(self, node_info: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check if prompt content contains template variables not wrapped in XML tags."""
        content = node_info["content"]
        line_number = node_info.get("line", 0)
        
        # Skip non-string content
        if not isinstance(content, str):
            return None
            
        if not content:
            return None
            
        # Find all template variables
        template_vars = self._extract_template_variables(content)
        if not template_vars:
            return None
            
        # Check if each template variable is wrapped in XML tags
        unwrapped_vars = []
        for var in template_vars:
            if not self._is_variable_wrapped_in_xml(content, var):
                unwrapped_vars.append(var)
        
        if unwrapped_vars:
            class MockNode:
                def __init__(self, line):
                    self.lineno = line
                    self.col_offset = 0
                    
            mock_node = MockNode(line_number)
            message = f"Template variable{'s' if len(unwrapped_vars) > 1 else ''} not wrapped in XML tags"
            return self._create_issue(mock_node, context, message=message, unwrapped_vars=unwrapped_vars)
        
        return None
    
    def _is_hub_pull(self, node):
        """Check if a node is a hub.pull() call."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "pull":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hub":
                return True
        return False
    
    def _extract_prompt_id(self, node):
        """Extract the prompt ID from a hub.pull() call."""
        if len(node.args) > 0:
            if isinstance(node.args[0], ast.Str):
                return node.args[0].s
            elif hasattr(ast, 'Constant') and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return node.args[0].value
        return None