# scanners/base_scanner.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from core.issue import Issue
from core.rule_framework import RuleApplier
from rules.base_rule import BaseRule

class BaseScanner(ABC):
    """
    Abstract base class for all scanners.
    
    This class provides common functionality for rule application,
    issue tracking, and scanner lifecycle management.
    """
    
    def __init__(self, rules: Optional[List[BaseRule]] = None):
        """
        Initialize the scanner with optional rules.
        
        Args:
            rules: Optional list of rule instances to use
        """
        self.rules = rules or []
        self.rule_applier = RuleApplier(self.rules)
        self.issues: List[Issue] = []
        
        # Track all scanned elements for comprehensive reporting
        self.scanned_elements = {}
    
    @abstractmethod
    def scan(self, ast_node: Any, context: Optional[Dict[str, Any]] = None) -> List[Issue]:
        """
        Scan the AST node and return a list of issues.
        
        Args:
            ast_node: The AST node to scan
            context: The context for the scan
            
        Returns:
            List of issues found
        """
        pass
    
    def register_issue(self, issue: Issue) -> None:
        """
        Register an issue found during scanning.
        
        Args:
            issue: The issue to register
        """
        self.issues.append(issue)
    
    def register_issues(self, issues: List[Issue]) -> None:
        """
        Register multiple issues at once.
        
        Args:
            issues: List of issues to register
        """
        self.issues.extend(issues)
        
    def reset(self) -> None:
        """Reset the scanner state for a new scan."""
        self.issues = []
        self.rule_applier.clear_issues()
        
    def record_scanned_element(self, element_type: str, element_data: Dict[str, Any]) -> None:
        """
        Record a scanned element for comprehensive reporting.
        
        Args:
            element_type: Type/category of the scanned element
            element_data: Data about the scanned element
        """
        if element_type not in self.scanned_elements:
            self.scanned_elements[element_type] = []
        
        self.scanned_elements[element_type].append(element_data)
    
    def apply_rules(self, target: Any, context: Dict[str, Any], **kwargs) -> List[Issue]:
        """
        Apply rules to a target.
        
        This is a convenience method that delegates to the rule applier
        and registers any issues found.
        
        Args:
            target: The target to apply rules to
            context: The context for rule application
            **kwargs: Additional arguments to pass to apply_rules
            
        Returns:
            List of issues found
        """
        issues = self.rule_applier.apply_rules(target, context, **kwargs)
        self.register_issues(issues)
        return issues
    
    def apply_rule_batch(self, targets: List[Any], context: Dict[str, Any], **kwargs) -> List[Issue]:
        """
        Apply rules to a batch of targets.
        
        Args:
            targets: List of targets to apply rules to
            context: The context for rule application
            **kwargs: Additional arguments to pass to apply_rule_batch
            
        Returns:
            List of issues found
        """
        issues = self.rule_applier.apply_rule_batch(targets, context, **kwargs)
        self.register_issues(issues)
        return issues
