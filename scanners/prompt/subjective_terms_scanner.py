import ast
import os
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from scanners.prompt.prompt_extractor import PromptExtractor
from rules.prompt.subjective_terms_rule import SubjectiveTermsRule


class SubjectiveTermsScanner(BaseScanner):
    """Scanner that detects subjective terms in prompts that may lead to unreliable or biased LLM output.
    
    This scanner reuses the prompt detection logic from PromptExtractor but applies
    specific rules to check for subjective terms like 'best', 'worst', 'key', etc.
    that can lead to ambiguous LLM responses when not properly defined.
    """
    
    def __init__(self):
        # Initialize with subjective terms rule
        rules = [SubjectiveTermsRule()]
        super().__init__(rules)
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan for subjective terms in prompts."""
        context = context or {}
        
        # Reuse the PromptExtractor to find prompts in the code
        extractor = PromptExtractor(context)
        
        # Extract and analyze prompts from the code
        if hasattr(ast_node, 'body'):
            extractor.visit(ast_node)
            prompts = extractor.prompts
            
            # Debug output
            if os.environ.get('DEBUG') == "1":
                print(f"SubjectiveTermsScanner: Found {len(prompts)} prompts to check in {context.get('file_name', 'unknown')}")
            
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
            
            # Apply rules to all extracted prompts
            prompt_data_list = []
            for prompt in prompts:
                prompt_data = {
                    'content': prompt.content,
                    'line': prompt.line_number,
                    'is_template': prompt.is_template,
                    'template_variables': prompt.template_variables
                }
                prompt_data_list.append(prompt_data)
            
            # Apply all rules to all prompts
            self.apply_rule_batch(prompt_data_list, context)
                        
        return self.issues