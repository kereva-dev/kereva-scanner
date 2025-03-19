"""
Tests for the SystemPromptScanner.

This test verifies that the scanner can detect:
1. Missing system prompts in LLM API calls
2. System instructions misplaced in user messages
"""

import ast
import os
import sys
import unittest
from pathlib import Path

# Add the project root to the path
sys.path.append(str(Path(__file__).parent.parent))

from scanners.prompt.system_prompt.system_prompt_scanner import SystemPromptScanner
from rules.prompt.system_prompt.missing_system_prompt_rule import MissingSystemPromptRule
from rules.prompt.system_prompt.misplaced_system_instruction_rule import MisplacedSystemInstructionRule


class TestSystemPromptScanner(unittest.TestCase):
    """Test cases for the SystemPromptScanner."""
    
    def setUp(self):
        self.scanner = SystemPromptScanner()
        
        # Sample code with various system prompt issues
        self.test_file = Path("examples/system_prompt_examples.py")
        self.assertTrue(self.test_file.exists(), f"Test file {self.test_file} does not exist")
        
        with open(self.test_file, "r") as f:
            self.code = f.read()
        
        self.tree = ast.parse(self.code)
        
    def test_missing_system_prompt_detection(self):
        """Test detection of missing system prompts."""
        # Run the scanner
        issues = self.scanner.scan(self.tree, {"file_name": str(self.test_file)})
        
        # Filter issues for missing system prompt
        missing_system_issues = [
            issue for issue in issues 
            if issue.rule_id == "missing-system-prompt"
        ]
        
        # We should find at least 2 instances (one for OpenAI, one for Anthropic)
        self.assertGreaterEqual(
            len(missing_system_issues), 
            2, 
            f"Expected to find at least 2 missing system prompt issues, found {len(missing_system_issues)}"
        )
        
        # Print detailed information about the issues found
        for issue in missing_system_issues:
            print(f"Found missing system prompt issue at line {issue.location.get('line', 0)}: {issue.message}")
        
    def test_misplaced_system_instruction_detection(self):
        """Test detection of system instructions misplaced in user messages."""
        # Run the scanner
        issues = self.scanner.scan(self.tree, {"file_name": str(self.test_file)})
        
        # Filter issues for misplaced system instructions
        misplaced_issues = [
            issue for issue in issues 
            if issue.rule_id == "misplaced-system-instruction"
        ]
        
        # We should find at least 2 instances
        self.assertGreaterEqual(
            len(misplaced_issues), 
            2, 
            f"Expected to find at least 2 misplaced system instruction issues, found {len(misplaced_issues)}"
        )
        
        # Print detailed information about the issues found
        for issue in misplaced_issues:
            print(f"Found misplaced system instruction issue at line {issue.location.get('line', 0)}: {issue.message}")
            
            # Verify that system_instructions is present in the context
            self.assertIsNotNone(issue.context)
            self.assertIn("system_instructions", issue.context)
    
    def test_developer_role_acceptance(self):
        """Test that developer role is recognized as a valid alternative to system role."""
        # Run the scanner
        issues = self.scanner.scan(self.tree, {"file_name": str(self.test_file)})
        
        # There should be no missing system prompt issues for the function using developer role
        for issue in issues:
            if issue.rule_id == "missing-system-prompt":
                self.assertNotIn(
                    "using_developer_role", 
                    issue.message, 
                    "Developer role was not recognized as a valid system role alternative"
                )


if __name__ == "__main__":
    unittest.main()