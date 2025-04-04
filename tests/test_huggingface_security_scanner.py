"""
Tests for the HuggingFace security scanners.
"""

import unittest
import ast
from pathlib import Path

from scanners.output.huggingface_security_scanner import HuggingFaceSecurityScanner
from rules.output.unsafe_huggingface_trust_remote_code_rule import UnsafeTrustRemoteCodeRule
from rules.output.unsafe_huggingface_serialization_rule import UnsafeSerializationRule

class TestHuggingFaceSecurityScanner(unittest.TestCase):
    
    def setUp(self):
        self.scanner = HuggingFaceSecurityScanner()
        self.safe_example_path = Path("examples/huggingface_secure_example.py")
        self.unsafe_example_path = Path("examples/huggingface_unsafe_example.py")
    
    def test_trust_remote_code_detection(self):
        """Test that trust_remote_code=True is properly detected."""
        code = """
from transformers import AutoModelForCausalLM, AutoTokenizer

# Unsafe usage with trust_remote_code=True
tokenizer = AutoTokenizer.from_pretrained("gpt2", trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained("gpt2", trust_remote_code=True)
        """
        
        tree = ast.parse(code)
        context = {"file_name": "test_code.py"}
        issues = self.scanner.scan(tree, context)
        
        # Should find 2 issues (one for tokenizer, one for model)
        self.assertEqual(len(issues), 2, f"Expected 2 issues, found {len(issues)}")
        
        # Verify rule ID and context
        for issue in issues:
            self.assertEqual(issue.rule_id, "output-unsafe-huggingface-trust-remote-code")
            self.assertIn("trust_remote_code=True", issue.message)
    
    def test_unsafe_serialization_detection(self):
        """Test that unsafe serialization formats are properly detected."""
        code = """
import torch
import pickle
from transformers import AutoModelForCausalLM

# Unsafe serialization methods
model = torch.load("model.pt")
with open("model.pkl", "rb") as f:
    data = pickle.load(f)
    
# Unsafe format with from_pretrained
model2 = AutoModelForCausalLM.from_pretrained("model.pkl")
        """
        
        tree = ast.parse(code)
        context = {"file_name": "test_code.py"}
        issues = self.scanner.scan(tree, context)
        
        # Should find 3 issues
        self.assertEqual(len(issues), 3, f"Expected 3 issues, found {len(issues)}")
        
        # Verify rule ID for serialization
        for issue in issues:
            self.assertEqual(issue.rule_id, "output-unsafe-huggingface-serialization")
    
    def test_multiple_unsafe_patterns(self):
        """Test detection of multiple unsafe patterns in the same file."""
        with open(self.unsafe_example_path, "r") as f:
            code = f.read()
        
        tree = ast.parse(code)
        context = {"file_name": str(self.unsafe_example_path)}
        issues = self.scanner.scan(tree, context)
        
        # Should find several issues (actual count depends on implementation complexity)
        self.assertGreater(len(issues), 3, f"Expected more than 3 issues, found {len(issues)}")
        
        # Verify mix of both rule types
        trust_remote_code_issues = [i for i in issues if i.rule_id == "output-unsafe-huggingface-trust-remote-code"]
        serialization_issues = [i for i in issues if i.rule_id == "output-unsafe-huggingface-serialization"]
        
        self.assertGreater(len(trust_remote_code_issues), 0, "Expected at least one trust_remote_code issue")
        self.assertGreater(len(serialization_issues), 0, "Expected at least one serialization issue")
    
    def test_safe_code_no_issues(self):
        """Test that safe code doesn't trigger false positives."""
        with open(self.safe_example_path, "r") as f:
            code = f.read()
        
        tree = ast.parse(code)
        context = {"file_name": str(self.safe_example_path)}
        issues = self.scanner.scan(tree, context)
        
        # Should find no issues
        self.assertEqual(len(issues), 0, f"Expected 0 issues in safe code, found {len(issues)}")


if __name__ == "__main__":
    unittest.main()