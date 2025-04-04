"""
Unsafe Output Scanner

Detects vulnerabilities where LLM output is used without proper sanitization in security-sensitive operations.
"""

import ast
import os
from typing import List, Dict, Set, Any, Optional, Tuple

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from rules.chain.unsafe_output_chain_rule import UnsafeOutputChainRule
from scanners.chain.chain_analyzer import ChainAnalyzer


class UnsafeOutputScanner(BaseScanner):
    """Scanner for detecting vulnerable LLM output usage without proper sanitization."""
    
    def __init__(self):
        # Initialize with the appropriate rule
        rules = [
            UnsafeOutputChainRule(),
        ]
        super().__init__(rules)
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Perform taint analysis on the AST to detect unsafe LLM output usage."""
        context = context or {}
        self.reset()  # Clear any previous issues
        
        debug = os.environ.get('DEBUG') == "1"
            
        if debug:
            print(f"UnsafeOutputScanner scanning file: {context.get('file_name', 'unknown')}")
            
        # Use the ChainAnalyzer to perform comprehensive analysis
        analyzer = ChainAnalyzer([])  # We don't need untrusted input sources for output checks
        analyzer.analyze(ast_node)
        vulnerabilities = analyzer.find_vulnerabilities()
        
        # Filter for only llm_to_unsafe_output vulnerabilities
        output_vulnerabilities = [
            vuln for vuln in vulnerabilities 
            if vuln.get("type") == "llm_to_unsafe_output"
        ]
        
        # Apply the rule to each vulnerability
        for vuln in output_vulnerabilities:
            line_number = self._find_line_number(vuln)
            vuln["line"] = line_number
            
            # Apply the rule to generate the issue
            issue = self.rules[0].check(vuln, context)
            if issue:
                self.register_issue(issue)
                
        if debug:
            print(f"Final count of issues: {len(self.issues)}")
                
        return self.issues
        
    def _find_line_number(self, vulnerability: Dict[str, Any]) -> int:
        """Extract a line number from a vulnerability."""
        # Try to find a line number in the path
        if "path" in vulnerability:
            # For unsafe execution (LLM output misuse), look for the sink line number
            if "sink" in vulnerability:
                sink_node = vulnerability["sink"]
                # Check if the sink node has a line number in its name (e.g. exec_call_42)
                if isinstance(sink_node, str) and "_" in sink_node:
                    try:
                        line_parts = sink_node.split("_")
                        if line_parts[-1].isdigit():
                            return int(line_parts[-1])
                    except (ValueError, IndexError):
                        pass
            
            # Check for LLM call nodes or sink operations in the path
            for node in reversed(vulnerability["path"]):  # Check in reverse to find sink first
                if isinstance(node, str):
                    if any(unsafe_op in node for unsafe_op in ["exec_", "eval_", "system_", "unsafe_", "shell_"]):
                        try:
                            return int(node.split("_")[-1])
                        except (ValueError, IndexError):
                            pass
                    elif node.startswith("llm_call_"):
                        try:
                            return int(node.split("_")[-1])
                        except (ValueError, IndexError):
                            pass
                    # Also look for other nodes that might contain line numbers
                    elif "_" in node:
                        parts = node.split("_")
                        if parts[-1].isdigit():
                            try:
                                return int(parts[-1])
                            except (ValueError, IndexError):
                                pass
        
        # If we have a line number directly in the vulnerability
        if "line" in vulnerability and isinstance(vulnerability["line"], int) and vulnerability["line"] > 0:
            return vulnerability["line"]
            
        # Last resort - try to determine based on source or exec line
        sink = vulnerability.get("sink", "")
        if isinstance(sink, str) and "_" in sink:
            try:
                return int(sink.split("_")[-1])
            except (ValueError, IndexError):
                pass
                
        # For unsafe execution, check for exec line in the path
        for key in vulnerability.keys():
            if isinstance(key, str) and key.startswith("exec_line_"):
                try:
                    return int(key.split("_")[-1])
                except (ValueError, IndexError):
                    pass
        
        # If we have the exec node itself
        if "exec_node" in vulnerability:
            exec_node = vulnerability["exec_node"]
            if hasattr(exec_node, "lineno"):
                return exec_node.lineno
                
        return 41  # Default to the line with exec() call as better default than line 1