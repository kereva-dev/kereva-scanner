"""
Tests for the SafeShellCommandsScanner.
"""

import ast
import sys
import os
import unittest

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanners.output.safe_shell_commands_scanner import SafeShellCommandsScanner

class TestSafeShellCommandsScanner(unittest.TestCase):
    """Test cases for the SafeShellCommandsScanner."""

    def setUp(self):
        """Set up the scanner for testing."""
        self.scanner = SafeShellCommandsScanner()

    def test_safe_ls_command(self):
        """Test a safe 'ls -l' command with LLM output."""
        code = """
import subprocess
from llm_api import get_response

# Get a path from LLM
llm_path = get_response("suggest a file path")

# Use ls -l with LLM output (safe)
subprocess.run(f"ls -l {llm_path}", shell=True)
"""
        tree = ast.parse(code)
        context = {
            "file_name": "test_file.py",
            "llm_output_vars": {"llm_path"}  # Manually set the LLM output variables
        }
        issues = self.scanner.scan(tree, context)
        self.assertEqual(len(issues), 0, "Should not detect issues for safe command")

    def test_unsafe_ls_command(self):
        """Test an unsafe 'ls -a' command with LLM output."""
        code = """
import subprocess
from llm_api import get_response

# Get a path from LLM
llm_path = get_response("suggest a file path")

# Use ls -a with LLM output (unsafe)
subprocess.run(f"ls -a {llm_path}", shell=True)
"""
        tree = ast.parse(code)
        context = {
            "file_name": "test_file.py",
            "llm_output_vars": {"llm_path"}  # Manually set the LLM output variables
        }
        issues = self.scanner.scan(tree, context)
        self.assertEqual(len(issues), 1, "Should detect issues for unsafe command arguments")
        self.assertIn("not on the safe list", issues[0].message, "Issue message should mention safe list")

    def test_unsafe_command(self):
        """Test an unsafe command (rm) with LLM output."""
        code = """
import os
from llm_api import get_response

# Get a path from LLM
llm_path = get_response("suggest a file path")

# Use rm with LLM output (unsafe)
os.system(f"rm {llm_path}")
"""
        tree = ast.parse(code)
        context = {
            "file_name": "test_file.py",
            "llm_output_vars": {"llm_path"}  # Manually set the LLM output variables
        }
        issues = self.scanner.scan(tree, context)
        self.assertEqual(len(issues), 1, "Should detect issues for unsafe commands")
        self.assertIn("not on the safe list", issues[0].message, "Issue message should mention safe list")

    def test_direct_llm_command(self):
        """Test direct execution of LLM command output."""
        code = """
import os
from llm_api import get_response

# Get a command from LLM
llm_command = get_response("suggest a shell command")

# Execute LLM command directly (unsafe)
os.system(llm_command)
"""
        tree = ast.parse(code)
        context = {
            "file_name": "test_file.py",
            "llm_output_vars": {"llm_command"}  # Manually set the LLM output variables
        }
        issues = self.scanner.scan(tree, context)
        self.assertEqual(len(issues), 1, "Should detect issues for direct command execution")

    def test_safe_echo_command(self):
        """Test a safe 'echo' command with LLM output."""
        code = """
import subprocess
from llm_api import get_response

# Get text from LLM
llm_text = get_response("suggest some text")

# Use echo with LLM output (safe, echo allows any arguments)
subprocess.run(["echo", llm_text])
"""
        tree = ast.parse(code)
        context = {
            "file_name": "test_file.py",
            "llm_output_vars": {"llm_text"}  # Manually set the LLM output variables
        }
        issues = self.scanner.scan(tree, context)
        self.assertEqual(len(issues), 0, "Should not detect issues for safe echo command")

if __name__ == "__main__":
    unittest.main()