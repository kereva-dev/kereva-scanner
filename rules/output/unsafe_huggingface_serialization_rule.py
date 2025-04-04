"""
Rule for detecting unsafe serialization formats in HuggingFace model operations.

This rule detects instances where potentially dangerous serialization formats
like pickle or PyTorch's native format are used without proper validation.
"""

import ast
from typing import Optional, Dict, Any, List

from rules.base_rule import BaseRule
from core.issue import Issue
from core.ast_utils import get_attribute_chain


class UnsafeSerializationRule(BaseRule):
    """Rule to detect unsafe serialization formats like pickle in model loading/saving."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-unsafe-huggingface-serialization",
            description="Using unsafe serialization formats can lead to arbitrary code execution",
            severity="high",
            tags=["security", "huggingface", "code-execution", "serialization"]
        )
        self.suggestion = "Avoid loading pickled models from untrusted sources. Use safetensors format instead."
        
        # Methods that involve serialization
        self.serialization_methods = [
            "from_pretrained",
            "save_pretrained",
            "load_state_dict",
            "torch.load",
            "pickle.load",
            "pickle.loads",
            "dill.load",
            "dill.loads",
            "joblib.load",
            "load"
        ]
        
        # Unsafe formats to watch for
        self.unsafe_formats = [
            "pickle", 
            ".pkl", 
            ".pickle", 
            ".pt", 
            ".pth", 
            ".bin",
            "pytorch_model.bin"
        ]
        
        # Safe alternatives to suggest
        self.safe_alternatives = [
            "safetensors", 
            ".safetensors"
        ]
    
    def check(self, node: ast.AST, context: Optional[Dict[str, Any]] = None) -> Optional[Issue]:
        """Check for unsafe serialization formats being used."""
        if not isinstance(node, ast.Call):
            return None
            
        # Handle direct references to unsafe formats in from_pretrained
        if self._is_from_pretrained_call(node):
            # Check if any format arguments are specified
            unsafe_format = self._check_format_arguments(node)
            if unsafe_format:
                return self._create_issue(node, context, unsafe_format)
                
            # Check if model_path or any string argument contains unsafe extension
            unsafe_path = self._check_path_arguments(node)
            if unsafe_path:
                return self._create_issue(node, context, unsafe_path)
        
        # Handle direct torch.load or pickle.load calls
        if self._is_direct_unsafe_load(node):
            return self._create_issue(node, context, self._get_load_method_name(node))
            
        return None
    
    def _is_from_pretrained_call(self, node: ast.Call) -> bool:
        """Check if this is a call to from_pretrained."""
        if not isinstance(node.func, ast.Attribute):
            return False
            
        attr_chain = get_attribute_chain(node.func)
        return len(attr_chain) >= 2 and attr_chain[-1] == "from_pretrained"
    
    def _is_direct_unsafe_load(self, node: ast.Call) -> bool:
        """Check if this is a direct call to an unsafe load method."""
        if isinstance(node.func, ast.Attribute):
            attr_chain = get_attribute_chain(node.func)
            method_name = ".".join(attr_chain)
            return any(unsafe_method in method_name for unsafe_method in [
                "torch.load", "pickle.load", "pickle.loads", "dill.load", "dill.loads", "joblib.load"
            ])
        elif isinstance(node.func, ast.Name) and node.func.id == "load":
            # Simple "load" function - check if it might be pickle/torch based on imports
            return True
            
        return False
        
    def _get_load_method_name(self, node: ast.Call) -> str:
        """Get the name of the load method being called."""
        if isinstance(node.func, ast.Attribute):
            return ".".join(get_attribute_chain(node.func))
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return "Unknown load method"
    
    def _check_format_arguments(self, node: ast.Call) -> Optional[str]:
        """Check for unsafe formats specified in keyword arguments."""
        for keyword in node.keywords:
            if keyword.arg in ["format", "file_format", "serialization_format"]:
                if isinstance(keyword.value, (ast.Str, ast.Constant)):
                    format_value = getattr(keyword.value, "s", None) or getattr(keyword.value, "value", None)
                    if format_value and any(unsafe in format_value.lower() for unsafe in self.unsafe_formats):
                        return format_value
                        
        return None
    
    def _check_path_arguments(self, node: ast.Call) -> Optional[str]:
        """Check if any string arguments contain unsafe file extensions."""
        # Check positional arguments first (model path is usually first arg)
        for arg in node.args:
            if isinstance(arg, (ast.Str, ast.Constant)):
                path_value = getattr(arg, "s", None) or getattr(arg, "value", None)
                if path_value and any(path_value.lower().endswith(ext) for ext in self.unsafe_formats):
                    return path_value
        
        # Check keyword arguments that might contain paths            
        for keyword in node.keywords:
            if keyword.arg in ["model_path", "pretrained_model_name_or_path", "filepath", "path"]:
                if isinstance(keyword.value, (ast.Str, ast.Constant)):
                    path_value = getattr(keyword.value, "s", None) or getattr(keyword.value, "value", None)
                    if path_value and any(path_value.lower().endswith(ext) for ext in self.unsafe_formats):
                        return path_value
                        
        return None
    
    def _create_issue(self, node: ast.Call, context: Dict[str, Any], unsafe_element: str) -> Issue:
        """Create an issue for unsafe serialization format usage."""
        file_name = context.get("file_name", "<unknown>")
        
        # Build a more specific message based on the unsafe element
        message = f"Security vulnerability: Using potentially unsafe serialization format"
        
        if any(format_name in unsafe_element.lower() for format_name in ["pickle", ".pkl", ".pickle"]):
            message = f"Security vulnerability: Using pickle serialization which can execute arbitrary code"
        elif any(format_name in unsafe_element.lower() for format_name in [".pt", ".pth", ".bin"]):
            message = f"Security vulnerability: Using PyTorch native serialization which can execute arbitrary code"
            
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
            severity=self.severity,
            fix_suggestion=self.suggestion,
            context={
                "unsafe_element": unsafe_element,
                "safe_alternatives": self.safe_alternatives
            },
            tags=self.tags
        )