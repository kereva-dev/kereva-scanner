"""
HuggingFace Security Scanner

This scanner detects security vulnerabilities in the usage of HuggingFace models,
including:
1. Using trust_remote_code=True which can lead to arbitrary code execution
2. Using unsafe serialization formats like pickle that can execute arbitrary code
"""

import ast
import os
from typing import List, Dict, Any, Optional, Set, Tuple

from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from rules.output.unsafe_huggingface_trust_remote_code_rule import UnsafeTrustRemoteCodeRule
from rules.output.unsafe_huggingface_serialization_rule import UnsafeSerializationRule


class HuggingFaceSecurityVisitor(BaseVisitor):
    """
    AST visitor to find HuggingFace-related API calls that might have security issues.
    This visitor collects calls to from_pretrained and serialization-related functions.
    """
    
    def __init__(self, context: Dict[str, Any]):
        super().__init__(context)
        self.huggingface_calls = []
        self.serialization_calls = []
        
        # Names that indicate HuggingFace model/tokenizer loading
        self.huggingface_classes = [
            "AutoModel", "AutoTokenizer", "AutoModelForCausalLM", "AutoModelForSeq2SeqLM",
            "PreTrainedModel", "PreTrainedTokenizer", "Pipeline", "TextGenerationPipeline"
        ]
        
        # Methods that involve serialization
        self.serialization_methods = [
            "from_pretrained", "save_pretrained", "load_state_dict", "load", 
            "torch.load", "pickle.load", "pickle.loads"
        ]
    
    def visit_Call(self, node: ast.Call) -> None:
        """Visit Call nodes to detect HuggingFace API usage."""
        # Check for from_pretrained and similar methods
        if isinstance(node.func, ast.Attribute) and node.func.attr == "from_pretrained":
            # Check if it's a HuggingFace class method
            if isinstance(node.func.value, ast.Name) and any(
                cls in node.func.value.id for cls in self.huggingface_classes
            ):
                self.huggingface_calls.append(node)
                
                # Also track serialization-related calls
                self.serialization_calls.append(node)
        
        # Check for direct serialization methods
        if isinstance(node.func, ast.Attribute):
            # Check for common serialization methods
            for method in self.serialization_methods:
                if method.endswith(node.func.attr) and "load" in node.func.attr:
                    self.serialization_calls.append(node)
                    break
        
        # Check for simple 'load' functions
        if isinstance(node.func, ast.Name) and node.func.id == "load":
            self.serialization_calls.append(node)
        
        # Continue traversing
        self.generic_visit(node)


class HuggingFaceSecurityScanner(BaseScanner):
    """
    Scanner for detecting security vulnerabilities in HuggingFace model usage.
    This scanner focuses on trust_remote_code and unsafe serialization formats.
    """
    
    def __init__(self):
        # Initialize with HuggingFace security rules
        rules = [
            UnsafeTrustRemoteCodeRule(),
            UnsafeSerializationRule()
        ]
        super().__init__(rules)
    
    def scan(self, ast_node: ast.AST, context: Optional[Dict[str, Any]] = None) -> List[Issue]:
        """
        Scan the AST for HuggingFace security vulnerabilities.
        
        Args:
            ast_node: The AST node to scan
            context: The context for the scan
            
        Returns:
            List of issues found
        """
        context = context or {}
        
        if os.environ.get('DEBUG') == "1":
            print(f"\nHuggingFaceSecurityScanner: Scanning {context.get('file_name', 'unknown')}")
        
        # Use the visitor to collect relevant call nodes
        visitor = HuggingFaceSecurityVisitor(context)
        visitor.visit(ast_node)
        
        # Debug output
        if os.environ.get('DEBUG') == "1":
            print(f"  Found {len(visitor.huggingface_calls)} HuggingFace method calls")
            print(f"  Found {len(visitor.serialization_calls)} serialization-related calls")
        
        # Apply rules to HuggingFace calls
        for node in visitor.huggingface_calls:
            # Apply the trust_remote_code rule to all HuggingFace calls
            self.apply_rules(node, context, filter_func=lambda rule: isinstance(rule, UnsafeTrustRemoteCodeRule))
        
        # Apply rules to serialization calls
        for node in visitor.serialization_calls:
            # Apply the serialization rule to all serialization-related calls
            self.apply_rules(node, context, filter_func=lambda rule: isinstance(rule, UnsafeSerializationRule))
        
        # Record all examined calls for comprehensive reporting
        for call in visitor.huggingface_calls:
            self.record_scanned_element("huggingface_calls", {
                "line": getattr(call, "lineno", 0),
                "api": f"{getattr(call.func.value, 'id', '')}.{call.func.attr}",
                "file": context.get('file_name', 'unknown')
            })
            
        for call in visitor.serialization_calls:
            call_name = "Unknown"
            if isinstance(call.func, ast.Attribute):
                if isinstance(call.func.value, ast.Name):
                    call_name = f"{call.func.value.id}.{call.func.attr}"
                else:
                    call_name = call.func.attr
            elif isinstance(call.func, ast.Name):
                call_name = call.func.id
                
            self.record_scanned_element("serialization_calls", {
                "line": getattr(call, "lineno", 0),
                "api": call_name,
                "file": context.get('file_name', 'unknown')
            })
            
        return self.issues