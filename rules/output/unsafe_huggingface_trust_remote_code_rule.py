"""
Rule for detecting unsafe use of trust_remote_code=True in HuggingFace model loading.

This rule detects instances where models are loaded with trust_remote_code=True,
which can lead to arbitrary code execution vulnerabilities.
"""

import ast
from typing import Optional, Dict, Any

from rules.base_rule import BaseRule
from core.issue import Issue
from core.ast_utils import get_attribute_chain


class UnsafeTrustRemoteCodeRule(BaseRule):
    """Rule to detect if models are loaded with trust_remote_code=True which can lead to code execution."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-unsafe-huggingface-trust-remote-code",
            description="Using trust_remote_code=True with HuggingFace model loading can lead to arbitrary code execution",
            severity="high",
            tags=["security", "huggingface", "code-execution"]
        )
        self.suggestion = "Avoid using trust_remote_code=True unless you fully trust the model source"
        
        # Methods that can use trust_remote_code parameter
        self.risky_methods = [
            "from_pretrained",
            "load_pretrained",
            "push_to_hub",
            "from_config"
        ]
        
        # Common classes that use these methods
        self.huggingface_classes = [
            "AutoTokenizer",
            "AutoModel",
            "AutoModelForCausalLM",
            "AutoModelForSeq2SeqLM",
            "AutoModelForSequenceClassification",
            "AutoModelForQuestionAnswering",
            "AutoModelForMaskedLM",
            "AutoModelForTokenClassification",
            "AutoConfig",
            "PreTrainedModel",
            "PreTrainedTokenizer",
            "PreTrainedTokenizerFast"
        ]
    
    def check(self, node: ast.AST, context: Optional[Dict[str, Any]] = None) -> Optional[Issue]:
        """Check if trust_remote_code=True is being used in any model loading method."""
        if not isinstance(node, ast.Call):
            return None
            
        # Verify this is a HuggingFace method call
        if not self._is_huggingface_method_call(node):
            return None
        
        # Check keyword arguments for trust_remote_code=True
        for keyword in node.keywords:
            if keyword.arg == "trust_remote_code":
                # Check if value is True
                if isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:
                    return self._create_issue(node, context)
                elif isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    return self._create_issue(node, context)
                elif isinstance(keyword.value, ast.Name):
                    # It's a variable, so we need to check context
                    # For now, we'll flag this as a potential issue
                    return self._create_issue(node, context, potential=True)
        
        return None
    
    def _is_huggingface_method_call(self, node: ast.Call) -> bool:
        """Check if this is a call to a HuggingFace class method that could use trust_remote_code."""
        if not isinstance(node.func, ast.Attribute):
            return False
            
        # Get the attribute chain (e.g., ["AutoModelForCausalLM", "from_pretrained"])
        attr_chain = get_attribute_chain(node.func)
        
        # Check if method is in risky_methods
        if len(attr_chain) < 2:
            return False
            
        method_name = attr_chain[-1]
        class_name = attr_chain[-2]
        
        # Check if this is a HuggingFace class using a risky method
        return (method_name in self.risky_methods and 
                (class_name in self.huggingface_classes or 
                 any(cls in class_name for cls in self.huggingface_classes)))
    
    def _create_issue(self, node: ast.Call, context: Dict[str, Any], potential: bool = False) -> Issue:
        """Create an issue for trust_remote_code=True usage."""
        # Get the method name for better error context
        attr_chain = get_attribute_chain(node.func)
        method_call = ".".join(attr_chain)
        
        message = f"{'Potential ' if potential else ''}Security vulnerability: Using trust_remote_code=True with {method_call}"
        if potential:
            message += " (variable value, needs verification)"
        
        file_name = context.get("file_name", "<unknown>")
        
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
                "method_call": method_call,
                "potential": potential
            },
            tags=self.tags
        )