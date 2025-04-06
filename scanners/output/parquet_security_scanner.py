"""
Parquet Security Scanner

This scanner detects security vulnerabilities in the usage of Apache Parquet files,
including:
1. Loading Parquet files from untrusted sources which could lead to remote code execution 
   via CVE-2025-30065 (applies to Apache Parquet < 1.15.1)
2. Identifying cases where user-supplied paths are used to load Parquet files
"""

import ast
import os
from typing import List, Dict, Any, Optional, Set, Tuple

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from rules.output.unsafe_parquet_loading_rule import UnsafeParquetLoadingRule


class ParquetSecurityVisitor(BaseVisitor):
    """
    AST visitor to find Parquet-related API calls that might have security issues.
    This visitor collects calls to read_parquet, ParquetFile, and other Parquet loading functions.
    """
    
    def __init__(self, context: Dict[str, Any]):
        super().__init__(context)
        self.parquet_loading_calls = []
        
        # Common function names for loading Parquet files
        self.parquet_functions = [
            "read_parquet", "ParquetFile", "ParquetDataset", "read_table",
            "open_dataset", "load_parquet", "parse_parquet"
        ]
        
        # Libraries that commonly use Parquet
        self.parquet_libraries = [
            "pandas", "pd", "pyarrow", "pa", "fastparquet", 
            "dask.dataframe", "dd", "polars", "pl"
        ]
    
    def visit_Call(self, node: ast.Call) -> None:
        """Visit Call nodes to detect Parquet file loading API usage."""
        # Check for direct function calls like read_parquet()
        if isinstance(node.func, ast.Name) and node.func.id in self.parquet_functions:
            self.parquet_loading_calls.append(node)
        
        # Check for method calls like pandas.read_parquet() or df.to_parquet()
        elif isinstance(node.func, ast.Attribute):
            # Check for methods on objects (like pandas.read_parquet)
            if node.func.attr in self.parquet_functions:
                # Check if this is a parquet library object
                if isinstance(node.func.value, ast.Name) and node.func.value.id in self.parquet_libraries:
                    self.parquet_loading_calls.append(node)
                else:
                    # Could still be a call like df.to_parquet - add it
                    self.parquet_loading_calls.append(node)
            
            # Check for more complex chains like pyarrow.parquet.read_table
            elif isinstance(node.func.value, ast.Attribute):
                # Check specifically for pyarrow.parquet.read_table pattern
                if (node.func.attr in ["read_table", "read_metadata"] and 
                    node.func.value.attr == "parquet" and 
                    isinstance(node.func.value.value, ast.Name) and
                    node.func.value.value.id in ["pyarrow", "pa"]):
                    self.parquet_loading_calls.append(node)
        
        # Continue traversing
        self.generic_visit(node)


class ParquetSecurityScanner(BaseScanner):
    """
    Scanner for detecting security vulnerabilities in Parquet file usage,
    focusing on potential remote code execution vulnerabilities like CVE-2025-30065.
    """
    
    def __init__(self):
        # Initialize with Parquet security rules
        rules = [
            UnsafeParquetLoadingRule()
        ]
        super().__init__(rules)
    
    def scan(self, ast_node: ast.AST, context: Optional[Dict[str, Any]] = None) -> List[Issue]:
        """
        Scan the AST for Parquet security vulnerabilities.
        
        Args:
            ast_node: The AST node to scan
            context: The context for the scan
            
        Returns:
            List of issues found
        """
        context = context or {}
        
        if os.environ.get('DEBUG') == "1":
            print(f"\nParquetSecurityScanner: Scanning {context.get('file_name', 'unknown')}")
        
        # Use the visitor to collect relevant call nodes
        visitor = ParquetSecurityVisitor(context)
        visitor.visit(ast_node)
        
        # Debug output
        if os.environ.get('DEBUG') == "1":
            print(f"  Found {len(visitor.parquet_loading_calls)} Parquet file loading calls")
        
        # Apply rules to Parquet loading calls
        for node in visitor.parquet_loading_calls:
            # Apply the Parquet loading rule to all detected calls
            self.apply_rules(node, context, filter_func=lambda rule: isinstance(rule, UnsafeParquetLoadingRule))
        
        # Record all examined calls for comprehensive reporting
        for call in visitor.parquet_loading_calls:
            call_name = "Unknown"
            if isinstance(call.func, ast.Attribute):
                if isinstance(call.func.value, ast.Name):
                    call_name = f"{call.func.value.id}.{call.func.attr}"
                else:
                    call_name = call.func.attr
            elif isinstance(call.func, ast.Name):
                call_name = call.func.id
                
            self.record_scanned_element("parquet_loading_calls", {
                "line": getattr(call, "lineno", 0),
                "api": call_name,
                "file": context.get('file_name', 'unknown')
            })
            
        return self.issues