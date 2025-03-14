"""
Comprehensive Reporter module

This module implements a reporter that logs all scanned elements,
not just those with vulnerabilities. This allows users to see the
complete scope of what was analyzed during a scan.
"""

import os
import json
import hashlib
import datetime
from typing import List, Dict, Any, Optional, Set
from core.issue import Issue

class ComprehensiveReporter:
    """
    Reporter that logs all scanned elements, including those without issues.
    
    This provides a complete picture of what was analyzed during a scan,
    which can be useful for audit purposes or to understand scan coverage.
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the comprehensive reporter.
        
        Args:
            output_dir: Directory where comprehensive logs will be saved (defaults to 'logs')
        """
        self.output_dir = output_dir or "logs"
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Track scanned elements by type
        self.scanned_elements = {
            "prompts": [],
            "llm_chains": [],
            "structured_output_models": [],
            "cached_prompts": [],
            "long_lists": [],
            "unsafe_outputs": [],
            "langchain_components": []
        }
    
    def add_scanned_element(self, element_type: str, element_data: Dict[str, Any]):
        """
        Add a scanned element to the comprehensive log.
        
        Args:
            element_type: Type of element (e.g., "prompts", "llm_chains")
            element_data: Data about the scanned element
        """
        if element_type in self.scanned_elements:
            # Add timestamp to the element
            element_data["timestamp"] = datetime.datetime.now().isoformat()
            self.scanned_elements[element_type].append(element_data)
        else:
            # Create a new category if it doesn't exist
            self.scanned_elements[element_type] = [element_data]
    
    def report(self, issues: List[Issue]) -> str:
        """
        Generate a comprehensive report of all scanned elements and issues.
        
        Args:
            issues: List of issues found during scanning
            
        Returns:
            Path to the generated comprehensive log file
        """
        # Create a unique filename based on timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"comprehensive_scan_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # Group issues by file for easier analysis
        files_dict = self._group_issues_by_file(issues)
        
        # Add file hashes for traceability
        for file_path in files_dict:
            if os.path.exists(file_path):
                files_dict[file_path]["file_hash"] = self._compute_file_hash(file_path)
        
        # Add metadata to the report
        report_data = {
            "metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "issue_count": len(issues),
                "file_count": len(files_dict),
                "elements_scanned": {
                    element_type: len(elements) 
                    for element_type, elements in self.scanned_elements.items()
                    if elements
                }
            },
            "scanned_elements": self.scanned_elements,
            "files": files_dict
        }
        
        # Write the report to the JSON file
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"Comprehensive report written to {filepath}")
        return filepath
    
    def _group_issues_by_file(self, issues: List[Issue]) -> Dict[str, Any]:
        """
        Group issues by file for better organization in the report.
        
        Args:
            issues: List of issues to group
            
        Returns:
            Dictionary with file paths as keys and issue lists as values
        """
        files_dict = {}
        
        for issue in issues:
            file_path = issue.location.get("file", "<unknown>")
            if file_path not in files_dict:
                files_dict[file_path] = {
                    "issues": [],
                    "issue_count": 0,
                    "severity_counts": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0
                    }
                }
            
            # Convert issue to a serializable dictionary
            issue_dict = {
                "rule_id": issue.rule_id,
                "message": issue.message,
                "location": issue.location,
                "severity": issue.severity,
                "fix_suggestion": issue.fix_suggestion,
                "context": issue.context
            }
            
            files_dict[file_path]["issues"].append(issue_dict)
            files_dict[file_path]["issue_count"] += 1
            
            # Update severity counts
            severity = issue.severity.lower()
            if severity in files_dict[file_path]["severity_counts"]:
                files_dict[file_path]["severity_counts"][severity] += 1
        
        return files_dict
    
    def _compute_file_hash(self, file_path: str) -> str:
        """
        Compute a SHA-256 hash of the file for traceability.
        
        Args:
            file_path: Path to the file to hash
            
        Returns:
            SHA-256 hash of the file content
        """
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()