"""
JSON Reporter module

This module implements a reporter that writes scan results to a JSON file.
It creates uniquely named files and includes file hashes for traceability.
"""

import os
import json
import hashlib
import datetime
from typing import List, Dict, Any, Optional
from core.issue import Issue

class JSONReporter:
    """
    Reporter that outputs scan results to a JSON file.
    
    This reporter creates a JSON file with a unique name based on the timestamp
    and includes file hashes to match results back to the original source files.
    """
    
    def __init__(self, output_dir: Optional[str] = None, github_url: Optional[str] = None, scan_target: Optional[str] = None):
        """
        Initialize the JSON reporter.
        
        Args:
            output_dir: Directory where JSON reports will be saved (defaults to 'scan_results')
            github_url: Base GitHub URL to prepend to relative file paths (optional)
            scan_target: The directory or file that was scanned (optional)
        """
        self.output_dir = output_dir or "scan_results"
        self.github_url = github_url
        self.scan_target = scan_target
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def report(self, issues: List[Issue]) -> str:
        """
        Report the issues by writing them to a JSON file.
        
        Args:
            issues: List of issues to report
            
        Returns:
            Path to the generated JSON file
        """
        # Create a unique filename based on timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.json"
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
            },
            "files": files_dict
        }
        
        # Write the report to the JSON file
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"JSON report written to {filepath}")
        return filepath
    
    def _group_issues_by_file(self, issues: List[Issue]) -> Dict[str, Any]:
        """
        Group issues by file for better organization in the JSON report.
        
        Args:
            issues: List of issues to group
            
        Returns:
            Dictionary with file paths as keys and issue lists as values
        """
        files_dict = {}
        
        for issue in issues:
            file_path = issue.location.get("file", "<unknown>")
            github_file_path = self._get_github_url(file_path) if self.github_url else file_path
            
            if github_file_path not in files_dict:
                files_dict[github_file_path] = {
                    "local_path": file_path,  # Keep the local path for reference
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
            
            # Create a copy of the location with the GitHub URL if available
            location = issue.location.copy()
            if self.github_url and "file" in location:
                location["file"] = self._get_github_url(location["file"])
                
            # Convert issue to a serializable dictionary
            issue_dict = {
                "rule_id": issue.rule_id,
                "message": issue.message,
                "location": location,
                "severity": issue.severity,
                "fix_suggestion": issue.fix_suggestion,
                "context": issue.context
            }
            
            files_dict[github_file_path]["issues"].append(issue_dict)
            files_dict[github_file_path]["issue_count"] += 1
            
            # Update severity counts
            severity = issue.severity.lower()
            if severity in files_dict[github_file_path]["severity_counts"]:
                files_dict[github_file_path]["severity_counts"][severity] += 1
        
        return files_dict
        
    def _get_github_url(self, file_path: str) -> str:
        """
        Convert a local file path to a GitHub URL.
        
        Args:
            file_path: Local file path
            
        Returns:
            GitHub URL for the file
        """
        if not self.github_url:
            return file_path
            
        # If the file_path already has a URL format, return it unchanged
        if "://" in file_path:
            return file_path
        
        # If we have a scan target, use it to determine the relative path
        if self.scan_target:
            from pathlib import Path
            
            # Convert to absolute paths to handle relative paths correctly
            abs_file_path = os.path.abspath(file_path)
            abs_scan_target = os.path.abspath(self.scan_target)
            
            # If the scan target is a file, use just the filename
            if os.path.isfile(abs_scan_target):
                path_for_url = os.path.basename(abs_file_path)
            else:
                # If the scan target is a directory, get the path relative to it
                try:
                    # This handles both files inside the scan target directory and files
                    # that might be specified through different paths but refer to the same location
                    rel_path = os.path.relpath(abs_file_path, abs_scan_target)
                    
                    # If the relative path starts with .. it means the file is not 
                    # under the scan target (should be rare but handle it)
                    if rel_path.startswith('..'):
                        path_for_url = os.path.basename(abs_file_path)
                    else:
                        # Use the relative path
                        path_for_url = rel_path.replace('\\', '/')  # Normalize for URLs
                except ValueError:
                    # If on different drives (Windows), fall back to filename
                    path_for_url = os.path.basename(abs_file_path)
        else:
            # Fallback if no scan target is provided
            path_for_url = os.path.basename(file_path)
            
        # Ensure the GitHub URL doesn't end with a slash
        base_url = self.github_url.rstrip('/')
        
        # Combine GitHub URL with the path
        return f"{base_url}/{path_for_url}"
    
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