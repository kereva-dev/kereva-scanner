"""
Unsafe Input Scanner

Detects vulnerabilities where untrusted user input flows to LLM API calls without proper sanitization.
"""

import ast
import os
from typing import List, Dict, Set, Any, Optional, Tuple

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.config import UNTRUSTED_INPUT_PATTERNS
from rules.chain.unsafe_input_rule import UnsafeInputRule
from rules.chain.unsafe_complete_chain_rule import UnsafeCompleteChainRule
from rules.output.unsafe_llm_output_usage_rule import UnsafeLLMOutputUsageRule
from scanners.chain.chain_analyzer import ChainAnalyzer


class UnsafeInputScanner(BaseScanner):
    """Scanner for detecting vulnerable LLM prompt chains with unsanitized inputs."""
    
    def __init__(self, untrusted_vars: Optional[List[str]] = None):
        # Initialize with the appropriate rules
        rules = [
            UnsafeInputRule(),
            UnsafeCompleteChainRule(),
            UnsafeLLMOutputUsageRule()
        ]
        super().__init__(rules)
        self.untrusted_vars = untrusted_vars or UNTRUSTED_INPUT_PATTERNS
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Perform full taint analysis on the AST to detect LLM chain vulnerabilities."""
        context = context or {}
        self.reset()  # Clear any previous issues
        
        debug = os.environ.get('DEBUG') == "1"
        
        # Allow context to override default untrusted vars
        if "untrusted_vars" in context:
            self.untrusted_vars = context["untrusted_vars"]
        
        # Add untrusted vars to the context so the rule has access to them
        context["untrusted_params"] = self.untrusted_vars
        
        if debug:
            print(f"UnsafeInputScanner scanning file: {context.get('file_name', 'unknown')}")
            print(f"Untrusted variables: {self.untrusted_vars}")
            
        # First approach: Apply the UnsafeInputRule directly to the AST
        # This will handle simpler cases but may miss complex taint flows
        self.apply_rules(ast_node, context)
        
        # Second approach: Use full taint analysis for complex flows
        # If no issues were found with the simple approach, or if we want to be thorough
        if not self.issues or context.get("thorough", True):
            # Use the ChainAnalyzer to perform comprehensive analysis
            analyzer = ChainAnalyzer(self.untrusted_vars)
            analyzer.analyze(ast_node)
            vulnerabilities = analyzer.find_vulnerabilities()
            
            # Apply the appropriate rule for each vulnerability
            for vuln in vulnerabilities:
                line_number = self._find_line_number(vuln)
                vuln["line"] = line_number
                
                # Map vulnerability type to the appropriate rule
                if vuln.get("type") == "untrusted_to_llm":
                    # Use UnsafeInputRule
                    rule = self.rules[0]
                elif vuln.get("type") == "unsafe_complete_chain":
                    # Use UnsafeCompleteChainRule
                    rule = self.rules[1]
                elif vuln.get("type") == "llm_to_unsafe_output":
                    # Use UnsafeLLMOutputUsageRule
                    rule = self.rules[2]
                else:
                    # Default to UnsafeInputRule
                    rule = self.rules[0]
                
                # Apply the rule to generate the issue
                issue = rule.check(vuln, context)
                if issue:
                    self.register_issue(issue)
                
        if debug:
            print(f"Final count of issues: {len(self.issues)}")
                
        return self.issues
        
    def _find_line_number(self, vulnerability: Dict[str, Any]) -> int:
        """Extract a line number from a vulnerability."""
        # Try to find a line number in the path
        if "path" in vulnerability:
            # First try to find an LLM call node which has the line number in its name
            for node in vulnerability["path"]:
                if isinstance(node, str) and node.startswith("llm_call_"):
                    try:
                        return int(node.split("_")[-1])
                    except (ValueError, IndexError):
                        pass
                
        return 1  # Return line 1 as a default