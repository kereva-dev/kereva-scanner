"""
Test cases for the UnsafeExecutionScanner
"""

import ast
import unittest
import sys
from pathlib import Path

# Add the project root to the path so we can import the modules
sys.path.append(str(Path(__file__).parent.parent))

from scanners.output import UnsafeExecutionScanner


class TestUnsafeOutputScanner(unittest.TestCase):
    """Test cases for the UnsafeExecutionScanner."""
    
    def test_detect_exec_vulnerability(self):
        """Test detection of exec vulnerability with LLM output."""
        code = """
import openai

def get_code():
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Write code for..."}]
    )
    return response.choices[0].message.content

code = get_code()
exec(code)  # Vulnerable!
"""
        tree = ast.parse(code)
        scanner = UnsafeExecutionScanner()
        issues = scanner.scan(tree, {"file_name": "test.py"})
        
        self.assertEqual(len(issues), 1, "Should detect one vulnerability")
        self.assertEqual(issues[0].rule_id, "output-unsafe-execution")
        self.assertIn("exec", issues[0].message)
    
    def test_detect_eval_vulnerability(self):
        """Test detection of eval vulnerability with LLM output."""
        code = """
import anthropic

client = anthropic.Anthropic(api_key="dummy")
response = client.messages.create(
    model="claude-2",
    max_tokens=100,
    messages=[{"role": "user", "content": "Write a Python expression"}]
)
expr = response.content[0].text
result = eval(expr)  # Vulnerable!
"""
        tree = ast.parse(code)
        scanner = UnsafeExecutionScanner()
        issues = scanner.scan(tree, {"file_name": "test.py"})
        
        self.assertEqual(len(issues), 1, "Should detect one vulnerability")
        self.assertEqual(issues[0].rule_id, "output-unsafe-execution")
        self.assertIn("eval", issues[0].message)
    
    def test_detect_os_system_vulnerability(self):
        """Test detection of os.system vulnerability with LLM output."""
        code = """
import os
import openai

def get_command():
    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": "Give me a Linux command"}]
    )
    return response.choices[0].message.content

cmd = get_command()
os.system(cmd)  # Vulnerable!
"""
        tree = ast.parse(code)
        scanner = UnsafeExecutionScanner()
        issues = scanner.scan(tree, {"file_name": "test.py"})
        
        self.assertEqual(len(issues), 1, "Should detect one vulnerability")
        self.assertEqual(issues[0].rule_id, "output-unsafe-execution")
        self.assertIn("os.system", issues[0].message)
    
    def test_detect_subprocess_vulnerability(self):
        """Test detection of subprocess vulnerability with LLM output."""
        code = """
import subprocess
import openai

def get_command():
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Give me a command"}]
    )
    cmd = response.choices[0].message.content
    return cmd

command = get_command()
result = subprocess.run(command, shell=True)  # Vulnerable!
"""
        tree = ast.parse(code)
        scanner = UnsafeExecutionScanner()
        issues = scanner.scan(tree, {"file_name": "test.py"})
        
        self.assertEqual(len(issues), 1, "Should detect one vulnerability")
        self.assertEqual(issues[0].rule_id, "output-unsafe-execution")
        self.assertIn("subprocess.run", issues[0].message)
    
    def test_no_false_positives(self):
        """Test that non-vulnerable code doesn't trigger false positives."""
        code = """
import subprocess
import openai

# This is safe because we're not using LLM output
safe_command = "ls -la"
subprocess.run(safe_command, shell=True)

def get_model_info():
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Tell me about gpt-4"}]
    )
    info = response.choices[0].message.content
    # Safe - just printing the LLM output
    print(info)
    return info
"""
        tree = ast.parse(code)
        scanner = UnsafeExecutionScanner()
        issues = scanner.scan(tree, {"file_name": "test.py"})
        
        self.assertEqual(len(issues), 0, "Should not detect any vulnerability")


if __name__ == "__main__":
    unittest.main()