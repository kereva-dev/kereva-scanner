"""
Rule for detecting unsafe Parquet file loading that could be vulnerable to CVE-2025-30065.

This rule detects instances where Parquet files are loaded without proper validation
or from untrusted sources, which could lead to remote code execution through
specially crafted files.
"""

import ast
from typing import Optional, Dict, Any, List

from rules.base_rule import BaseRule
from core.issue import Issue
from core.ast_utils import get_attribute_chain


class UnsafeParquetLoadingRule(BaseRule):
    """Rule to detect unsafe Parquet file loading that could be vulnerable to remote code execution."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-unsafe-parquet-loading",
            description="Loading Parquet files from untrusted sources can lead to remote code execution (CVE-2025-30065)",
            severity="critical",
            tags=["security", "data-loading", "code-execution", "parquet", "cve-2025-30065"]
        )
        self.suggestion = "Validate the source of Parquet files before loading. Consider implementing checksumming, " \
                          "signature verification, or running in a sandboxed environment."
        
        # Common methods for loading Parquet files
        self.parquet_loading_methods = [
            "read_parquet",
            "ParquetFile",
            "ParquetDataset",
            "read_table",
            "pq.read_table",
            "fastparquet.ParquetFile",
            "parquet.ParquetFile",
            "open_dataset",
            "load_parquet",
            "parse_parquet"
        ]
        
        # Keywords that might indicate untrusted sources
        self.untrusted_source_indicators = [
            "user", "input", "upload", "external", "file", "request", 
            "http", "https", "download", "remote", "client", "url",
            "s3", "storage", "web", "database"
        ]
        
        # Libraries that commonly use Parquet
        self.parquet_libraries = [
            "pandas", "pd",
            "pyarrow", "pa",
            "fastparquet",
            "dask.dataframe", "dd",
            "polars", "pl",
            "dataset", "datasets",
            "databricks"
        ]
    
    def check(self, node: ast.AST, context: Optional[Dict[str, Any]] = None) -> Optional[Issue]:
        """Check for unsafe Parquet file loading patterns."""
        if not isinstance(node, ast.Call):
            return None
            
        # Check if this is a Parquet loading call
        if self._is_parquet_loading_call(node):
            # First check if there's direct evidence of untrusted input
            untrusted_source = self._check_untrusted_source(node)
            if untrusted_source:
                return self._create_issue(node, context, untrusted_source)
            
            # Otherwise warn about any Parquet loading as potentially vulnerable
            method_name = self._get_parquet_loading_method(node)
            return self._create_issue(node, context, method_name, is_untrusted_confirmed=False)
                
        return None
    
    def _is_parquet_loading_call(self, node: ast.Call) -> bool:
        """Check if this is a call to a Parquet loading function."""
        # Direct function call: read_parquet()
        if isinstance(node.func, ast.Name) and node.func.id in self.parquet_loading_methods:
            return True
            
        # Method call: pandas.read_parquet() or df.to_parquet()
        if isinstance(node.func, ast.Attribute):
            # Check for methods like .read_parquet
            if node.func.attr in self.parquet_loading_methods:
                return True
                
            # Check for fully qualified calls
            attr_chain = get_attribute_chain(node.func)
            if len(attr_chain) >= 2:
                # Check for patterns like pandas.read_parquet or pyarrow.parquet.read_table
                library = attr_chain[0]
                method = attr_chain[-1]
                
                if library in self.parquet_libraries and method in self.parquet_loading_methods:
                    return True
                    
                # Special case for pyarrow.parquet.read_table
                if len(attr_chain) >= 3 and library in self.parquet_libraries and attr_chain[1] == "parquet" and method in self.parquet_loading_methods:
                    return True
        
        return False
        
    def _get_parquet_loading_method(self, node: ast.Call) -> str:
        """Get the name of the Parquet loading method being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            attr_chain = get_attribute_chain(node.func)
            return ".".join(attr_chain)
        return "Unknown Parquet loading method"
    
    def _check_untrusted_source(self, node: ast.Call) -> Optional[str]:
        """Check if the Parquet file might be from an untrusted source."""
        # Check positional arguments that might be file paths
        for arg in node.args:
            if isinstance(arg, (ast.Str, ast.Constant)):
                path_value = getattr(arg, "s", None) or getattr(arg, "value", None)
                if path_value and any(indicator in str(path_value).lower() for indicator in self.untrusted_source_indicators):
                    return str(path_value)
            
            # Check for variable names that suggest untrusted input
            elif isinstance(arg, ast.Name) and any(indicator in arg.id.lower() for indicator in self.untrusted_source_indicators):
                return arg.id
        
        # Check keyword arguments that might contain paths
        for keyword in node.keywords:
            if keyword.arg in ["path", "filepath", "source", "file", "input_file", "location"]:
                if isinstance(keyword.value, (ast.Str, ast.Constant)):
                    path_value = getattr(keyword.value, "s", None) or getattr(keyword.value, "value", None)
                    if path_value and any(indicator in str(path_value).lower() for indicator in self.untrusted_source_indicators):
                        return f"{keyword.arg}={path_value}"
                
                # Check for variable names that suggest untrusted input
                elif isinstance(keyword.value, ast.Name) and any(indicator in keyword.value.id.lower() for indicator in self.untrusted_source_indicators):
                    return f"{keyword.arg}={keyword.value.id}"
                    
        return None
    
    def _create_issue(self, node: ast.Call, context: Dict[str, Any], unsafe_element: str, is_untrusted_confirmed: bool = True) -> Issue:
        """Create an issue for unsafe Parquet file loading."""
        file_name = context.get("file_name", "<unknown>")
        
        # Build a specific message based on whether we've confirmed untrusted input
        if is_untrusted_confirmed:
            message = f"Critical security vulnerability: Potentially unsafe loading of Parquet files from untrusted source"
            severity = self.severity
        else:
            message = f"Potential security vulnerability: Parquet file loading may be vulnerable to CVE-2025-30065"
            severity = "medium"  # Lower severity for cases where we can't confirm untrusted source
            
        # Add the specific unsafe element to the message
        message += f" ({unsafe_element})"
        
        return Issue(
            rule_id=self.rule_id,
            message=message,
            location={
                "line": getattr(node, "lineno", 0),
                "column": getattr(node, "col_offset", 0),
                "file": file_name
            },
            severity=severity,
            fix_suggestion=self.suggestion,
            context={
                "unsafe_element": unsafe_element,
                "cve": "CVE-2025-30065",
                "untrusted_confirmed": is_untrusted_confirmed
            },
            tags=self.tags
        )