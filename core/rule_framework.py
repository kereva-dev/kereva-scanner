"""
Standardized rule application framework for scanners.

This module provides a common approach to rule registration, filtering,
and application across different scanner types. It helps reduce code
duplication and enforce consistent rule handling.
"""

import importlib
import inspect
import os
import pkgutil
from typing import Dict, List, Optional, Any, Type, Set, Callable
from abc import ABC

from rules.base_rule import BaseRule
from core.issue import Issue


class RuleRegistry:
    """
    A registry for rule classes that enables dynamic discovery and instantiation.
    
    The registry keeps track of all available rules, their categories, and dependencies.
    It supports rule filtering, ordering, and lazy loading to optimize performance.
    """
    
    def __init__(self):
        self._rules: Dict[str, Type[BaseRule]] = {}
        self._rule_categories: Dict[str, Set[str]] = {}
        self._rule_dependencies: Dict[str, List[str]] = {}
    
    def register_rule(self, rule_class: Type[BaseRule], 
                     categories: Optional[List[str]] = None,
                     dependencies: Optional[List[str]] = None) -> None:
        """
        Register a rule class in the registry.
        
        Args:
            rule_class: The rule class to register
            categories: Optional list of categories this rule belongs to
            dependencies: Optional list of rule IDs this rule depends on
        """
        # Get the rule ID from a temporary instance
        temp_instance = rule_class()
        rule_id = temp_instance.rule_id
        
        # Register the rule class
        self._rules[rule_id] = rule_class
        
        # Register categories
        if categories:
            for category in categories:
                if category not in self._rule_categories:
                    self._rule_categories[category] = set()
                self._rule_categories[category].add(rule_id)
        
        # Register dependencies
        if dependencies:
            self._rule_dependencies[rule_id] = dependencies
    
    def discover_rules(self, package_name: str) -> None:
        """
        Automatically discover and register rules from a package.
        
        Args:
            package_name: The name of the package to discover rules in (e.g., 'rules')
        """
        package = importlib.import_module(package_name)
        for _, name, is_pkg in pkgutil.iter_modules(package.__path__, package.__name__ + '.'):
            if is_pkg:
                # Recursively search subpackages
                self.discover_rules(name)
            else:
                # Import the module and check for rule classes
                module = importlib.import_module(name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    # Check if it's a class that inherits from BaseRule
                    if (inspect.isclass(attr) and 
                        issubclass(attr, BaseRule) and
                        attr is not BaseRule and
                        not inspect.isabstract(attr)):
                        
                        # Get categories from module structure
                        parts = name.split('.')
                        if len(parts) > 2:
                            category = parts[-2]  # Use the parent directory name as category
                            self.register_rule(attr, categories=[category])
                        else:
                            self.register_rule(attr)
    
    def get_rule_classes(self, category: Optional[str] = None) -> List[Type[BaseRule]]:
        """
        Get all rule classes, optionally filtered by category.
        
        Args:
            category: Optional category to filter rules by
            
        Returns:
            List of rule classes
        """
        if category:
            if category not in self._rule_categories:
                return []
            return [self._rules[rule_id] for rule_id in self._rule_categories[category]]
        else:
            return list(self._rules.values())
    
    def create_rules(self, category: Optional[str] = None, 
                   include_rules: Optional[List[str]] = None,
                   exclude_rules: Optional[List[str]] = None) -> List[BaseRule]:
        """
        Create instances of rules, with optional filtering.
        
        Args:
            category: Optional category to filter rules by
            include_rules: Optional list of rule IDs to include
            exclude_rules: Optional list of rule IDs to exclude
            
        Returns:
            List of instantiated rule objects
        """
        rule_classes = self.get_rule_classes(category)
        
        # Filter by included rules if specified
        if include_rules:
            rule_classes = [cls for cls in rule_classes 
                         if cls().rule_id in include_rules]
        
        # Filter out excluded rules
        if exclude_rules:
            rule_classes = [cls for cls in rule_classes 
                         if cls().rule_id not in exclude_rules]
        
        # Instantiate the rules
        return [cls() for cls in rule_classes]
    
    def get_rule_class(self, rule_id: str) -> Optional[Type[BaseRule]]:
        """Get a rule class by its ID."""
        return self._rules.get(rule_id)


class RuleApplier:
    """
    Handles the application of rules to targets, collecting and processing issues.
    
    This class standardizes how rules are applied across different scanners,
    reducing code duplication and ensuring consistent behavior.
    """
    
    def __init__(self, rules: List[BaseRule]):
        """
        Initialize the rule applier with a list of rules.
        
        Args:
            rules: List of rule instances to apply
        """
        self.rules = rules
        self.issues: List[Issue] = []
    
    def apply_rules(self, 
                  target: Any, 
                  context: Dict[str, Any], 
                  filter_func: Optional[Callable[[BaseRule], bool]] = None,
                  transform_func: Optional[Callable[[Any, Dict[str, Any]], Any]] = None) -> List[Issue]:
        """
        Apply rules to a target, collecting issues.
        
        Args:
            target: The object to apply rules to (AST node, prompt content, etc.)
            context: Context information for rule application
            filter_func: Optional function to filter which rules should be applied
            transform_func: Optional function to transform the target before application
            
        Returns:
            List of issues found
        """
        new_issues = []
        
        # Filter rules if requested
        applicable_rules = self.rules
        if filter_func:
            applicable_rules = [rule for rule in self.rules if filter_func(rule)]
        
        # Apply each rule
        for rule in applicable_rules:
            # Check if rule should be skipped due to exclusions
            if self._should_skip_rule(rule, target, context):
                continue
                
            # Transform the target if requested
            actual_target = target
            if transform_func:
                actual_target = transform_func(target, context)
            
            # Apply the rule
            issue = rule.check(actual_target, context)
            if issue:
                new_issues.append(issue)
        
        # Add the new issues to the overall list
        self.issues.extend(new_issues)
        return new_issues
        
    def _should_skip_rule(self, rule: BaseRule, node: Any, context: Dict[str, Any]) -> bool:
        """
        Check if a rule should be skipped based on exclusion comments.
        
        Args:
            rule: The rule to check
            node: The AST node being checked
            context: The context for rule application
            
        Returns:
            True if the rule should be skipped, False otherwise
        """
        # If no exclusions in context, don't skip
        if "exclusions" not in context:
            return False
            
        exclusions = context["exclusions"]
        
        # If the node has lineno attribute, check if that line has exclusions
        if hasattr(node, "lineno") and node.lineno in exclusions:
            exclusion_info = exclusions[node.lineno]
            
            # If the line is completely ignored, skip the rule
            if exclusion_info["type"] == "ignore":
                return True
                
            # If rules are specified for disabling, check if this rule is in the list
            if exclusion_info["type"] == "disable":
                # If rules list is empty, all rules are disabled for this line
                if not exclusion_info["rules"]:
                    return True
                    
                # Skip if this rule's ID is in the disabled rules
                return rule.rule_id in exclusion_info["rules"]
        
        # Otherwise, don't skip the rule
        return False
    
    def apply_rule_batch(self,
                       targets: List[Any],
                       context: Dict[str, Any],
                       filter_func: Optional[Callable[[BaseRule], bool]] = None,
                       transform_func: Optional[Callable[[Any, Dict[str, Any]], Any]] = None) -> List[Issue]:
        """
        Apply rules to a batch of targets.
        
        Args:
            targets: List of objects to apply rules to
            context: Context information for rule application
            filter_func: Optional function to filter which rules should be applied
            transform_func: Optional function to transform each target before application
            
        Returns:
            List of issues found
        """
        all_new_issues = []
        for target in targets:
            # apply_rules already handles exclusions
            new_issues = self.apply_rules(target, context, filter_func, transform_func)
            all_new_issues.extend(new_issues)
        
        return all_new_issues
    
    def clear_issues(self) -> None:
        """Clear all collected issues."""
        self.issues = []
    
    def get_issues(self) -> List[Issue]:
        """Get all collected issues."""
        return self.issues