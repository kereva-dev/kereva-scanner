"""
Test for the XMLTagRule.
"""

import ast
import sys
from pathlib import Path

# Add the project root to the path so we can import the modules
sys.path.append(str(Path(__file__).parent.parent))

from rules.prompt.xml_tags.simple_rule import XMLTagRule

def test_xml_tag_rule():
    # Test code that should trigger the rule
    test_code = """
import openai

def unsafe_function():
    user_input = "Tell me about yourself"
    
    # This should be flagged - user input not wrapped in XML tags
    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_input}
        ]
    )
    
    return response

def safe_function():
    user_input = "Tell me about yourself"
    
    # This should be safe - user input wrapped in XML tags
    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": f"<user_input>{user_input}</user_input>"}
        ]
    )
    
    return response
"""

    # Parse the code
    tree = ast.parse(test_code)
    
    # Create the rule
    rule = XMLTagRule()
    
    # Run the check
    context = {"file_name": "test_file.py", "code": test_code}
    issue = rule.check(tree, context)
    
    # We should find an issue
    assert issue is not None, "Rule should have found an issue"
    assert "user_input" in issue.message, "Issue message should mention the variable name"
    
    print("XMLTagRule test passed!")

if __name__ == "__main__":
    test_xml_tag_rule()