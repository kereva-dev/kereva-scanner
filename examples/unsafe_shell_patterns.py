"""
Example showing specific unsafe shell command patterns that should be detected.
"""

import os
import subprocess
import openai

def get_command_from_llm():
    """Get a command from an LLM."""
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Suggest a shell command"}]
    )
    return response.choices[0].message.content

def get_path_from_llm():
    """Get a path from an LLM."""
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Suggest a file path"}]
    )
    return response.choices[0].message.content

def test_unsafe_patterns():
    """Test various unsafe shell command patterns with LLM output."""
    # Get values from LLM
    llm_path = get_path_from_llm()
    llm_command = get_command_from_llm()
    
    # 1. Direct execution of LLM command - MOST DANGEROUS
    os.system(llm_command)
    
    # 2. Unsafe 'ls -a' with LLM path (the -a flag is not on safe list)
    os.system(f"ls -a {llm_path}")
    
    # 3. Unsafe 'rm' command with LLM path
    os.system(f"rm {llm_path}")
    
    # 4. Unsafe 'find' command with LLM path
    os.system(f"find {llm_path} -type f")
    
    # 5. Mixed safe/unsafe: Using a safe command (ls -l) with a dangerous one
    os.system(f"ls -l {llm_path}; rm -rf {llm_path}")

if __name__ == "__main__":
    test_unsafe_patterns()