"""
Rule for detecting unsafe complete chains (input->LLM->output).

This module defines a rule that checks for complete chains where untrusted input
flows to an LLM and then its output is used unsafely without proper sanitization.
"""

import ast
from typing import Any, Optional, Dict, List, Set
from rules.base_rule import BaseRule
from core.issue import Issue

class UnsafeCompleteChainRule(BaseRule):
    """Rule to detect unsafe complete chains (input->LLM->output) without proper sanitization."""
    
    def __init__(self):
        super().__init__(
            rule_id="chain-unsanitized-complete-chain",  # Fix: Changed to be consistent with the naming pattern
            description="Untrusted input flows through LLM to unsafe output usage without proper sanitization",
            severity="critical",
            tags=["security", "sanitization", "prompt-engineering", "output-safety"]
        )
    
    def check(self, node_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if there's an unsafe complete chain."""
        context = context or {}
        
        # For this rule, we expect a dictionary with vulnerability information
        if isinstance(node_info, dict) and node_info.get('type') == 'unsafe_complete_chain':
            source = node_info.get('source', '')
            sink = node_info.get('sink', '')
            path = node_info.get('path', [])
            
            # Get source code context and code snippet if available
            source_code = context.get('code', '')
            code_snippet = None
            lineno = node_info.get('line', 0)
            
            if source_code and lineno:
                # Get up to 3 lines of context around the line of code
                lines = source_code.split('\n')
                start_line = max(0, lineno - 2)
                end_line = min(len(lines), lineno + 1)
                code_snippet = '\n'.join(lines[start_line:end_line])
            
            # Create more detailed context information
            issue_context = {
                'source': source,
                'sink': sink,
                'path': ' -> '.join(str(p) for p in path) if path else '',
                'code_snippet': code_snippet
            }
            
            return Issue(
                rule_id=self.rule_id,
                message=f"Unsafe complete chain: untrusted input '{source}' flows through LLM to unsafe operation '{sink}' without proper sanitization",
                location={
                    'file': context.get('file_name', '<unknown>'),
                    'line': lineno
                },
                severity=self.severity,
                fix_suggestion="Implement proper input validation before the LLM call and output sanitization after the LLM call to prevent security vulnerabilities.",
                context=issue_context,
                tags=self.tags
            )
        
        return None