import ast
import os
from typing import List, Dict, Any, Optional
from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from core.ast_utils import extract_string_value
from rules.prompt.inefficient_caching_rule import InefficientCachingRule


class InefficientCachingScanner(BaseScanner):
    """Scanner for prompt caching inefficiencies."""
    
    def __init__(self, min_prompt_length: int = 200):
        # Initialize with the inefficient caching rule
        rules = [
            InefficientCachingRule(min_prompt_length=min_prompt_length)
        ]
        super().__init__(rules)
    
    def deduplicate_issues(self) -> None:
        """Remove duplicate issues based on rule_id and location."""
        if not self.issues:
            return
            
        unique_issues = {}
        for issue in self.issues:
            # Create a unique key based on rule_id and location
            key = (
                issue.rule_id,
                issue.location.get("line"),
                issue.location.get("file")
            )
            unique_issues[key] = issue
            
        # Replace the issues list with deduplicated issues
        self.issues = list(unique_issues.values())
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan for prompt caching inefficiencies using the rule framework."""
        context = context or {}
        self.reset()  # Clear any previous issues
        visitor = PromptCachingVisitor(context)
        # Print only in debug mode
        if os.environ.get('DEBUG') == "1":
            print(f"InefficientCachingScanner scanning file: {context.get('file_name', 'unknown')}")
        
        # Apply the rule directly to each assignment node using the rule framework
        # Filter for the InefficientCachingRule
        inefficient_caching_rules = [rule for rule in self.rules if rule.rule_id == "prompt-inefficient-caching"]
        
        if inefficient_caching_rules:
            # Create a visitor to find all assignments that might be prompts
            class AssignmentVisitor(ast.NodeVisitor):
                def __init__(self, scanner, rules, rule_applier, context):
                    self.scanner = scanner
                    self.rules = rules
                    self.rule_applier = rule_applier
                    self.context = context
                    
                def visit_Assign(self, node):
                    if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                        var_name = node.targets[0].id
                        if os.environ.get('DEBUG') == "1":
                            print(f"  Checking assignment to variable: {var_name}")
                        
                    # Apply rules and collect any new issues
                    new_issues = self.rule_applier.apply_rules(
                        node, 
                        self.context, 
                        filter_func=lambda rule: rule.rule_id == "prompt-inefficient-caching"
                    )
                    
                    if new_issues:
                        if os.environ.get('DEBUG') == "1":
                            print(f"  Found {len(new_issues)} issues in variable assignment")
                        # Register the issues with the scanner
                        self.scanner.register_issues(new_issues)
                    
                    self.generic_visit(node)
            
            # Visit all AST nodes looking for potential prompt assignments
            visitor = AssignmentVisitor(self, inefficient_caching_rules, self.rule_applier, context)
            visitor.visit(ast_node)
            
            # Get issues from the rule applier but avoid duplicates
            self.deduplicate_issues()
            
            if os.environ.get('DEBUG') == "1":
                print(f"Final count of issues: {len(self.issues)}")
        
        return self.issues


class PromptCachingVisitor(BaseVisitor):
    """AST visitor to find inefficient prompt caching patterns."""
    
    def __init__(self, context: Dict[str, Any]):
        super().__init__(context)
    
    def visit_Assign(self, node):
        """Visit assignment nodes to track variables."""
        # Track variable assignments
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            
            # Track the variable value for potential later reference
            if isinstance(node.value, ast.JoinedStr):
                # It's an f-string
                self.variables[var_name] = {
                    "node": node.value,
                    "line": node.lineno,
                    "is_fstring": True
                }
            elif isinstance(node.value, ast.Call) and hasattr(node.value, 'func'):
                # Check for strip(), format(), etc.
                if isinstance(node.value.func, ast.Attribute) and node.value.func.attr in ['strip', 'format']:
                    if isinstance(node.value.func.value, ast.JoinedStr):  # "f-string".strip()
                        self.variables[var_name] = {
                            "node": node.value.func.value,
                            "line": node.lineno,
                            "is_fstring": True
                        }
            else:
                # Other string-like value
                content = extract_string_value(node.value)
                if content:
                    self.variables[var_name] = {
                        "value": content,
                        "line": node.lineno,
                        "is_fstring": False
                    }
        
        # Continue visiting child nodes
        super().visit_Assign(node)