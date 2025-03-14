import ast
import unittest
import sys
from pathlib import Path

# Add the project root to the path so we can import the modules
sys.path.append(str(Path(__file__).parent.parent))

from scanners.chain import UnsafeInputScanner

class TestLLMChainScanner(unittest.TestCase):
    """Tests for the UnsafeInputScanner."""
    
    def test_unsafe_chain_detection(self):
        """Test that the scanner detects unsafe LLM chains."""
        # Sample code with an unsafe LLM chain
        unsafe_code = """
def unsafe_function(user_input):
    # Direct use of user input in LLM call
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=user_input,
        max_tokens=100
    )
    result = response.choices[0].text
    return result
"""
        # Parse the code
        tree = ast.parse(unsafe_code)
        
        # Initialize the scanner with a list of untrusted variables
        scanner = UnsafeInputScanner(untrusted_vars=["user_input"])
        
        # Scan the code
        issues = scanner.scan(tree, {"file_path": "test_file.py"})
        
        # Check that we found at least one issue
        self.assertTrue(len(issues) > 0, "Scanner did not detect the unsafe LLM chain")
        
        # Check that the issue has the correct properties
        issue = issues[0]
        self.assertEqual(issue.rule_id, "chain-unsafe-input")
        self.assertEqual(issue.severity, "high")
        self.assertIn("user_input", issue.message)
    
    def test_safe_chain_no_detection(self):
        """Test that the scanner does not flag safe LLM chains."""
        # Sample code with a safe LLM chain (sanitization is in place)
        safe_code = """
def safe_function(user_input):
    # Sanitize the input
    allowed_commands = ["help", "summarize", "translate"]
    if user_input in allowed_commands:
        sanitized_input = user_input
    else:
        sanitized_input = "Invalid command"
    
    # Use sanitized input in LLM call
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=sanitized_input,
        max_tokens=100
    )
    result = response.choices[0].text
    return result
"""
        # Parse the code
        tree = ast.parse(safe_code)
        
        # Initialize the scanner with a list of untrusted variables
        scanner = UnsafeInputScanner(untrusted_vars=["user_input"])
        
        # Scan the code
        issues = scanner.scan(tree, {"file_path": "test_file.py"})
        
        # Check that we found no issues
        self.assertEqual(len(issues), 0, "Scanner incorrectly flagged a safe LLM chain")


if __name__ == "__main__":
    unittest.main()