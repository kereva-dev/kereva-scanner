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
            
            # Filter vulnerabilities based on exclusion comments
            filtered_vulnerabilities = []
            
            # Get exclusions from context if available
            exclusions = context.get("exclusions", {})
            
            for vuln in vulnerabilities:
                # Extract rule_id and path variables
                rule_id = vuln.get("rule_id", "")
                path = vuln.get("path", [])
                
                # Check if the path contains any variables that have been excluded
                should_exclude = False
                if rule_id == "chain-unsanitized-input" and path:
                    path_elements = path
                    if isinstance(path, str):
                        path_elements = path.split(" -> ")
                    elif not isinstance(path, list):
                        path_elements = [str(path)]
                    
                    # Check each element in the path
                    for element in path_elements:
                        # Check if this element is excluded by line
                        for line, excl_info in exclusions.items():
                            # If it's a disable directive for this rule
                            if (excl_info.get("type") == "disable" and 
                                "chain-unsanitized-input" in excl_info.get("rules", [])):
                                # Check if the line contains this variable name
                                with open(context.get("file_name", ""), 'r') as f:
                                    lines = f.readlines()
                                    if 0 <= line - 1 < len(lines):
                                        if element in lines[line - 1] and '=' in lines[line - 1]:
                                            var_name = lines[line - 1].split('=')[0].strip()
                                            if var_name == element:
                                                should_exclude = True
                                                if debug:
                                                    print(f"Excluding vulnerability with {element} in path due to line {line} exclusion")
                                                break
                        if should_exclude:
                            break
                
                # Only add vulnerabilities that should not be excluded
                if not should_exclude:
                    filtered_vulnerabilities.append(vuln)
            
            # Apply the appropriate rule for each filtered vulnerability
            for vuln in filtered_vulnerabilities:
                line_number = self._find_line_number(vuln)
                vuln["line"] = line_number
                
                # If the vulnerability comes with a rule_id, use that to find the appropriate rule
                if "rule_id" in vuln:
                    rule_id = vuln.get("rule_id")
                    # Find the rule with the matching rule_id
                    matching_rule = next((r for r in self.rules if r.rule_id == rule_id), None)
                    if matching_rule:
                        rule = matching_rule
                    else:
                        # Fall back to mapping by type if no matching rule found
                        if vuln.get("type") == "untrusted_to_llm":
                            rule = self.rules[0]  # UnsafeInputRule
                        elif vuln.get("type") == "unsafe_complete_chain":
                            rule = self.rules[1]  # UnsafeCompleteChainRule 
                        elif vuln.get("type") == "llm_to_unsafe_output":
                            rule = self.rules[2]  # UnsafeLLMOutputUsageRule
                        else:
                            rule = self.rules[0]  # Default to UnsafeInputRule
                else:
                    # Map vulnerability type to the appropriate rule as before
                    if vuln.get("type") == "untrusted_to_llm":
                        rule = self.rules[0]  # UnsafeInputRule
                    elif vuln.get("type") == "unsafe_complete_chain":
                        rule = self.rules[1]  # UnsafeCompleteChainRule
                    elif vuln.get("type") == "llm_to_unsafe_output":
                        rule = self.rules[2]  # UnsafeLLMOutputUsageRule
                    else:
                        rule = self.rules[0]  # Default to UnsafeInputRule
                
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
            # Different vulnerability types require different strategies
            vuln_type = vulnerability.get("type", "")
            
            # For unsafe execution (LLM output misuse), look for the sink line number
            if vuln_type == "llm_to_unsafe_output" and "sink" in vulnerability:
                sink_node = vulnerability["sink"]
                # Check if the sink node has a line number in its name (e.g. exec_call_42)
                if isinstance(sink_node, str) and "_" in sink_node:
                    try:
                        line_parts = sink_node.split("_")
                        if line_parts[-1].isdigit():
                            return int(line_parts[-1])
                    except (ValueError, IndexError):
                        pass
            
            # For unsafe complete chain, prioritize finding the sink operation
            if vuln_type == "unsafe_complete_chain":
                # Try to find the exec or unsafe operation in the path
                for node in reversed(vulnerability["path"]):  # Check in reverse to find sink first
                    if isinstance(node, str):
                        if any(unsafe_op in node for unsafe_op in ["exec_", "eval_", "system_", "unsafe_", "shell_"]):
                            try:
                                return int(node.split("_")[-1])
                            except (ValueError, IndexError):
                                pass
            
            # For all vulnerability types, check for LLM call nodes in the path
            for node in vulnerability["path"]:
                if isinstance(node, str) and node.startswith("llm_call_"):
                    try:
                        return int(node.split("_")[-1])
                    except (ValueError, IndexError):
                        pass
                
                # Also look for other nodes that might contain line numbers
                elif isinstance(node, str) and "_" in node:
                    parts = node.split("_")
                    if parts[-1].isdigit():
                        try:
                            return int(parts[-1])
                        except (ValueError, IndexError):
                            pass
            
            # If we have source and sink, use the sink line number if available
            if "source" in vulnerability and "sink" in vulnerability:
                sink = vulnerability["sink"]
                if isinstance(sink, str) and "_" in sink:
                    try:
                        potential_line = sink.split("_")[-1]
                        if potential_line.isdigit():
                            return int(potential_line)
                    except (ValueError, IndexError):
                        pass
        
        # If we have a line number directly in the vulnerability
        if "line" in vulnerability and isinstance(vulnerability["line"], int) and vulnerability["line"] > 0:
            return vulnerability["line"]
            
        # Last resort - try to determine based on source or exec line
        source = vulnerability.get("source", "")
        if isinstance(source, str) and "_" in source:
            try:
                return int(source.split("_")[-1])
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