"""
Rule for detecting unsafe usage of LLM outputs.

This module defines a rule that checks if LLM outputs are being used unsafely
without proper sanitization or validation.
"""

import ast
from typing import Any, Optional, Dict, List, Set
from rules.base_rule import BaseRule
from core.issue import Issue

class UnsafeLLMOutputUsageRule(BaseRule):
    """Rule to detect unsafe usage of LLM outputs."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-unsafe-llm-usage",
            description="LLM output is used unsafely without proper validation or sanitization",
            severity="high",
            tags=["security", "sanitization", "output-safety"]
        )
    
    def check(self, node_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if LLM output is used unsafely."""
        context = context or {}
        
        # For this rule, we expect a dictionary with vulnerability information
        if isinstance(node_info, dict) and node_info.get('type') == 'llm_to_unsafe_output':
            source = node_info.get('source', '')  # LLM output variable
            sink = node_info.get('sink', '')      # Unsafe output usage
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
                message=f"LLM output '{source}' flows to potentially unsafe operation '{sink}' without proper sanitization",
                location={
                    'file': context.get('file_name', '<unknown>'),
                    'line': lineno
                },
                severity=self.severity,
                fix_suggestion="Validate and sanitize LLM outputs before using them in operations that could lead to security issues.",
                context=issue_context,
                tags=self.tags
            )
        
        return None