from typing import List
from core.issue import Issue

class ConsoleReporter:
    """A simple reporter that outputs issues to the console."""
    
    def report(self, issues: List[Issue]) -> None:
        """Print issues to the console in a readable format."""
        if not issues:
            print("No issues found!")
            return
            
        print(f"Found {len(issues)} issues:\n")
        
        for i, issue in enumerate(issues, 1):
            self._print_issue(i, issue)
    
    def _print_issue(self, index: int, issue: Issue) -> None:
        """Print a single issue with formatting."""
        severity_colors = {
            "high": "\033[91m",  # Red
            "medium": "\033[93m",  # Yellow
            "low": "\033[94m",  # Blue
            "info": "\033[92m"   # Green
        }
        reset = "\033[0m"
        
        severity_color = severity_colors.get(issue.severity.lower(), "")
        
        # Format location
        location = ""
        if isinstance(issue.location, dict):
            if "file" in issue.location and "line" in issue.location:
                location = f"{issue.location['file']}:{issue.location['line']}"
            elif "path" in issue.location and "line" in issue.location:
                location = f"{issue.location['path']}:{issue.location['line']}"
            elif "file" in issue.location:
                location = f"{issue.location['file']}"
            elif "line" in issue.location:
                location = f"Line {issue.location['line']}"
        
        # Print header
        print(f"Issue #{index}: {severity_color}{issue.rule_id} ({issue.severity}){reset}")
        print(f"Location: {location}")
        print(f"Message: {issue.message}")
        
        # Print tags if available
        if issue.tags:
            print(f"Tags: {', '.join(issue.tags)}")
        
        # Print fix suggestion if available
        if issue.fix_suggestion:
            print(f"Suggestion: {issue.fix_suggestion}")
        
        # Print context if available and not empty
        if issue.context and any(issue.context.values()):
            print("Context:")
            for key, value in issue.context.items():
                if value:  # Only print non-empty values
                    print(f"  {key}: {value}")
        
        print()  # Empty line between issues