import ast
import os
from typing import List, Dict, Any, Type, Tuple, Optional
from pathlib import Path
from core.issue import Issue
from scanners.base_scanner import BaseScanner
from core.notebook_utils import extract_code_from_notebook, get_original_cell_number

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
            
            # Store line mapping in context so it can be used to map back to cells
            context = {
                "file_name": str(notebook_path),
                "code": code,
                "offline_mode": self.offline_mode,
                "is_notebook": True,
                "line_mapping": line_mapping
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
                
                # Map line numbers to cells for each issue
                for issue in scanner_issues:
                    if "line" in issue.location:
                        line = issue.location["line"]
                        cell_num = get_original_cell_number(line, line_mapping)
                        issue.location["cell"] = cell_num
                        # Enhance the message with cell info
                        issue.message = f"Cell #{cell_num}: {issue.message}"
                        
                self.issues.extend(scanner_issues)
                
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
                "offline_mode": self.offline_mode
            }
            
            for i, scanner in enumerate(self.scanners):
                if os.environ.get('DEBUG') == "1":
                    print(f"  - Running scanner {i+1}: {scanner.__class__.__name__}")
                # Reset scanner state
                scanner.reset()
                scanner_issues = scanner.scan(tree, context)
                if os.environ.get('DEBUG') == "1":
                    print(f"  - Scanner found {len(scanner_issues)} issues")
                self.issues.extend(scanner_issues)
            
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
