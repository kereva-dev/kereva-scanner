import ast
import os
from typing import List, Optional, Dict, Any, Set

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from core.ast_utils import extract_string_value, extract_fstring, extract_fstring_vars
from scanners.prompt.prompt_extractor import PromptExtractor

from rules.prompt.xml_tags.simple_rule import XMLTagRule
from rules.prompt.xml_tags.unused_tags_rule import UnusedXMLTagsRule
from rules.prompt.xml_tags.langchain_rule import LangChainXMLTagRule
from rules.prompt.xml_tags.list_protection_rule import ListProtectionXMLRule


class XMLTagsScanner(BaseScanner):
    """Scanner for XML tag-related issues in prompts."""
    
    def __init__(self):
        # Initialize with XML tag rules
        rules = [
            XMLTagRule(), 
            UnusedXMLTagsRule(),
            LangChainXMLTagRule(),  # Rule for LangChain-specific XML tag usage
            ListProtectionXMLRule()  # Rule for protecting lists in prompts with XML tags
        ]
        super().__init__(rules)
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan for XML tag-related issues in prompts."""
        context = context or {}
        extractor = PromptExtractor(context)
        
        # First, apply XML tag rules directly to the AST node
        self.apply_rules(ast_node, context)
                
        # Then, extract and analyze prompts from the code
        if hasattr(ast_node, 'body'):
            extractor.visit(ast_node)
            prompts = extractor.prompts
            
            # Debug output
            if os.environ.get('DEBUG') == "1":
                print(f"XMLTagsScanner: Found {len(prompts)} prompts in {context.get('file_name', 'unknown')}")
                for i, prompt in enumerate(prompts):
                    content_display = str(prompt.content) if prompt.content else ""
                    if len(content_display) > 50:
                        content_display = content_display[:50] + "..."
                    print(f"  Prompt {i+1}: {prompt.line_number}, '{content_display}'")
            
            # Record all prompts for comprehensive reporting
            for prompt in prompts:
                self.record_scanned_element("prompts", {
                    "content": prompt.content,
                    "line_number": prompt.line_number,
                    "variable_name": prompt.variable_name,
                    "is_template": prompt.is_template,
                    "template_variables": prompt.template_variables,
                    "api_call": prompt.api_call,
                    "file": context.get('file_name', 'unknown')
                })
            
            # Apply rules to all extracted prompts as a batch
            prompt_data_list = []
            for prompt in prompts:
                prompt_data = {
                    'content': prompt.content,
                    'line': prompt.line_number,
                    'is_template': prompt.is_template,
                    'template_variables': prompt.template_variables
                }
                prompt_data_list.append(prompt_data)
            
            # Apply XML tag rules to all prompts in a batch
            rule_filter = lambda rule: rule.rule_id.startswith("prompt-xml")
            
            # Explicitly apply the UnusedXMLTagsRule before general rule application
            unused_tags_rule = next((r for r in self.rules if isinstance(r, UnusedXMLTagsRule)), None)
            
            # Debug output and explicit rule application for UnusedXMLTagsRule
            if os.environ.get('DEBUG') == "1":
                print("Explicitly checking for unused XML tags in prompts:")
                
            if unused_tags_rule:
                for i, prompt_data in enumerate(prompt_data_list):
                    if os.environ.get('DEBUG') == "1":
                        print(f"Checking prompt {i+1} for unused XML tags:")
                    
                    content = prompt_data.get('content', '')
                    if content:
                        tags = unused_tags_rule._extract_xml_tags(content)
                        if tags:
                            if os.environ.get('DEBUG') == "1":
                                print(f"  Found tags: {tags}")
                                
                            unused = unused_tags_rule._find_unused_tags(content, tags)
                            if unused:
                                if os.environ.get('DEBUG') == "1":
                                    print(f"  Unused tags: {unused}")
                                    print(f"  Will create issue at line {prompt_data.get('line', 0)}")
                                
                                # Directly create and register an issue
                                issue = unused_tags_rule.check(prompt_data, context)
                                if issue:
                                    self.register_issue(issue)
                
            # Apply all XML tag rules to all prompts in a batch    
            self.apply_rule_batch(prompt_data_list, context, filter_func=rule_filter)
                        
        return self.issues
        
    def check_list_xml_protection(self, list_data, context=None) -> List[Issue]:
        """
        Specifically check if lists in prompts are properly protected with XML tags.
        
        This method is designed to be used by other scanners (like LongListScanner)
        to check if list data is properly protected with XML tags.
        
        Args:
            list_data: Dictionary with information about the list
            context: Scanning context
            
        Returns:
            List of issues found
        """
        context = context or {}
        
        # Find the list protection rule
        list_protection_rule = next((r for r in self.rules if isinstance(r, ListProtectionXMLRule)), None)
        
        if list_protection_rule:
            # Apply the rule to the list data
            issue = list_protection_rule.check(list_data, context)
            if issue:
                return [issue]
        
        return []