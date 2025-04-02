import ast
import os
from typing import List, Dict, Any, Type, Tuple, Optional
from pathlib import Path
from core.issue import Issue
from scanners.base_scanner import BaseScanner
from core.notebook_utils import extract_code_from_notebook, get_original_cell_number
from core.ast_utils import extract_line_comments, parse_exclusion_comments

class Analyzer:
    """Main orchestrator for code analysis."""
    
    def __init__(self, offline_mode=False):
        self.scanners = []
        self.issues = []
        self.offline_mode = offline_mode
    
    def register_scanner(self, scanner: BaseScanner):
        """Register a scanner to be used during analysis."""
        self.scanners.append(scanner)
    
    def analyze_file(self, file_path: Path) -> List[Issue]:
        """Analyze a single file and return issues."""
        if file_path.suffix == '.ipynb':
            return self.analyze_notebook(file_path)
        else:
            with open(file_path, 'r') as f:
                code = f.read()
            return self.analyze_code(code, str(file_path))
            
    def analyze_notebook(self, notebook_path: Path) -> List[Issue]:
        """Analyze a Jupyter notebook file and return issues."""
        if os.environ.get('DEBUG') == "1":
            print(f"\nAnalyzer.analyze_notebook for {notebook_path}")
            
        try:
            # Extract code from notebook cells
            code, line_mapping = extract_code_from_notebook(notebook_path)
            
            # Extract comments from the extracted code for exclusion processing
            comments = extract_line_comments(code)
            exclusions = parse_exclusion_comments(comments)
            
            if os.environ.get('DEBUG') == "1" and exclusions:
                print(f"  - Found {len(exclusions)} exclusion comments in notebook")
                for line, info in exclusions.items():
                    print(f"    - Line {line}: {info['type']} {info.get('rules', '')}")
            
            # Store line mapping in context so it can be used to map back to cells
            context = {
                "file_name": str(notebook_path),
                "code": code,
                "offline_mode": self.offline_mode,
                "is_notebook": True,
                "line_mapping": line_mapping,
                "exclusions": exclusions  # Add exclusions to context
            }
            
            # Parse extracted code
            try:
                tree = ast.parse(code, filename=str(notebook_path))
            except SyntaxError as e:
                # Map synthetic line number to cell number
                cell_num = get_original_cell_number(e.lineno, line_mapping)
                issue = Issue(
                    rule_id="syntax-error",
                    message=f"Syntax error in cell #{cell_num}: {str(e)}",
                    location={"line": e.lineno, "column": e.offset, "file": str(notebook_path), "cell": cell_num},
                    severity="error"
                )
                return [issue]
                
            # Run scanners on the code
            self.issues = []
            for scanner in self.scanners:
                scanner.reset()
                scanner_issues = scanner.scan(tree, context)
                
                # Filter out issues that should be excluded based on comments
                filtered_issues = []
                for issue in scanner_issues:
                    if self._should_include_issue(issue, exclusions):
                        # Map line numbers to cells for each issue
                        if "line" in issue.location:
                            line = issue.location["line"]
                            cell_num = get_original_cell_number(line, line_mapping)
                            issue.location["cell"] = cell_num
                            # Enhance the message with cell info
                            issue.message = f"Cell #{cell_num}: {issue.message}"
                            
                        filtered_issues.append(issue)
                
                if os.environ.get('DEBUG') == "1":
                    print(f"  - Scanner found {len(scanner_issues)} issues, {len(filtered_issues)} after exclusion filtering")
                
                self.issues.extend(filtered_issues)
                
            return self.issues
                
        except Exception as e:
            if os.environ.get('DEBUG') == "1":
                print(f"  - Error analyzing notebook: {e}")
            issue = Issue(
                rule_id="notebook-error",
                message=f"Error analyzing notebook: {str(e)}",
                location={"file": str(notebook_path)},
                severity="error"
            )
            return [issue]
    
    def analyze_code(self, code: str, file_name: str = "<unknown>") -> List[Issue]:
        """Analyze code string and return issues."""
        if os.environ.get('DEBUG') == "1":
            print(f"\nAnalyzer.analyze_code for {file_name}")
        
        # Reset issues for this new file
        self.issues = []
        
        try:
            # Extract comments from source code for exclusion processing
            comments = extract_line_comments(code)
            exclusions = parse_exclusion_comments(comments)
            
            if os.environ.get('DEBUG') == "1" and exclusions:
                print(f"  - Found {len(exclusions)} exclusion comments")
                for line, info in exclusions.items():
                    print(f"    - Line {line}: {info['type']} {info.get('rules', '')}")
            
            tree = ast.parse(code, filename=file_name)
            if os.environ.get('DEBUG') == "1":
                print(f"  - Successfully parsed AST")
                
                # Print some information about the AST to help debugging
                from ast import dump
                ast_dump = dump(tree, annotate_fields=False)
                print(f"  - AST structure (truncated): {ast_dump[:100]}...")
            
            context = {
                "file_name": file_name, 
                "code": code,
                "offline_mode": self.offline_mode,
                "exclusions": exclusions  # Add exclusions to context
            }
            
            for i, scanner in enumerate(self.scanners):
                if os.environ.get('DEBUG') == "1":
                    print(f"  - Running scanner {i+1}: {scanner.__class__.__name__}")
                # Reset scanner state
                scanner.reset()
                scanner_issues = scanner.scan(tree, context)
                
                # Filter out issues that should be excluded based on comments
                filtered_issues = []
                for issue in scanner_issues:
                    if self._should_include_issue(issue, exclusions):
                        filtered_issues.append(issue)
                
                if os.environ.get('DEBUG') == "1":
                    print(f"  - Scanner found {len(scanner_issues)} issues, {len(filtered_issues)} after exclusion filtering")
                self.issues.extend(filtered_issues)
            
            return self.issues
        except SyntaxError as e:
            if os.environ.get('DEBUG') == "1":
                print(f"  - Syntax error in file: {e}")
            issue = Issue(
                rule_id="syntax-error",
                message=f"Syntax error: {str(e)}",
                location={"line": e.lineno, "column": e.offset, "file": file_name},
                severity="error"
            )
            self.issues.append(issue)
            return self.issues
            
    def _should_include_issue(self, issue: Issue, exclusions: Dict[int, Dict[str, Any]]) -> bool:
        """
        Determine if an issue should be included based on exclusion comments.
        
        Args:
            issue: The issue to check
            exclusions: Dictionary mapping line numbers to exclusion information
            
        Returns:
            True if the issue should be included, False if it should be excluded
        """
        # If the issue doesn't have a line number, we can't exclude it
        if "line" not in issue.location:
            return True
            
        line = issue.location["line"]
        
        # Check if the line is in the exclusions
        if line in exclusions:
            exclusion_info = exclusions[line]
            
            # If the line is completely ignored, exclude the issue
            if exclusion_info["type"] == "ignore":
                return False
                
            # If specific rules are disabled, check if this rule is among them
            if exclusion_info["type"] == "disable":
                # If rules is empty, all rules are disabled for this line
                if not exclusion_info["rules"]:
                    return False
                    
                # Check if the rule ID is in the disabled rules
                return issue.rule_id not in exclusion_info["rules"]
        
        # Special handling for chain-unsanitized-input where we need to check 
        # if any variable in its path is excluded
        if issue.rule_id == "chain-unsanitized-input" and issue.context and "path" in issue.context:
            path = issue.context["path"]
            # Check if path contains any excluded variables
            for path_element in path.split(" -> "):
                for excl_line, excl_info in exclusions.items():
                    # Skip lines that aren't disable or don't have chain-unsanitized-input in rules
                    if excl_info["type"] != "disable" or "chain-unsanitized-input" not in excl_info.get("rules", []):
                        continue
                    
                    # Get variable name from this line if it's a variable assignment
                    with open(issue.location.get("file", ""), 'r') as f:
                        lines = f.readlines()
                        if 0 <= excl_line - 1 < len(lines):
                            line_content = lines[excl_line - 1]
                            # Very simple assignment detection (this could be more robust)
                            if "=" in line_content:
                                var_name = line_content.split("=")[0].strip()
                                # If this variable is in our path, exclude the issue
                                if var_name == path_element:
                                    return False
        
        # If no exclusion applies, include the issue
        return True
