import ast
import os
from typing import List, Dict, Any, Type
from pathlib import Path
from core.issue import Issue
from scanners.base_scanner import BaseScanner

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
        with open(file_path, 'r') as f:
            code = f.read()
        
        return self.analyze_code(code, str(file_path))
    
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
