"""
Example showing both safe and unsafe patterns for shell command execution with LLM outputs.
This demonstrates the safe shell commands scanner features.
"""

import os
import subprocess
import openai
from anthropic import Anthropic

# Configure API clients
openai.api_key = "dummy-api-key"
anthropic = Anthropic(api_key="dummy-api-key")

def get_command_from_llm():
    """Get a shell command from an LLM."""
    # Simulate LLM response
    response = anthropic.completions.create(
        prompt="\n\nHuman: Suggest a Linux command to list files in the current directory\n\nAssistant:",
        max_tokens_to_sample=300,
        model="claude-2"
    )
    # Extract command from response
    llm_command = response.completion.strip()
    
    # For testing, the LLM would have returned something like "ls -la" or another command
    # which would be in the llm_command variable
    return llm_command

def get_path_from_llm():
    """Get a file path from an LLM."""
    # Simulate LLM response
    response = anthropic.completions.create(
        prompt="\n\nHuman: Suggest a file path to look at\n\nAssistant:",
        max_tokens_to_sample=300,
        model="claude-2"
    )
    # Extract file path from response
    llm_path = response.completion.strip()
    
    # For testing, the LLM would have returned something like "/etc/passwd" or another path
    # which would be in the llm_path variable
    return llm_path

def safe_execution_examples():
    """Examples of safe shell command execution with LLM outputs."""
    # Get values from LLM
    llm_command = get_command_from_llm()
    file_path = get_path_from_llm()
    
    # SAFE: Using ls -l with LLM-generated path (ls -l is on safe list)
    print("Running safe command: ls -l " + file_path)
    subprocess.run(f"ls -l {file_path}", shell=True)
    
    # SAFE: Using cat without flags on LLM-generated path (cat without flags is on safe list)
    print("Running safe command: cat " + file_path)
    os.system(f"cat {file_path}")
    
    # SAFE: Using echo with any arguments (echo is on safe list with "*")
    print("Running safe command: echo " + llm_command)
    subprocess.run(["echo", llm_command])
    
    # SAFE: Using grep with allowed flags
    print("Running safe command: grep -i pattern " + file_path)
    subprocess.run(["grep", "-i", "pattern", file_path])

def unsafe_execution_examples():
    """Examples of unsafe shell command execution with LLM outputs."""
    # Get values from LLM
    llm_command = get_command_from_llm()
    file_path = get_path_from_llm()
    
    # SHOULD BE FLAGGED: Using ls -a with LLM-generated path (ls -a is not on safe list)
    print("Running unsafe command: ls -a " + file_path)
    # The -a flag is not on the safe list for ls, so this should be detected
    subprocess.run(f"ls -a {file_path}", shell=True)
    
    # UNSAFE: Using find command with LLM-generated path (find is not on safe list)
    print("Running unsafe command: find " + file_path)
    os.system(f"find {file_path} -type f")
    
    # UNSAFE: Using rm command with LLM-generated path (rm is not on safe list)
    print("Running unsafe command: rm " + file_path)
    subprocess.run(f"rm {file_path}", shell=True)
    
    # THIS SHOULD DEFINITELY BE DETECTED! Directly executing LLM-generated command
    # a direct LLM variable passed to os.system is always unsafe since we can't know what command it contains
    print("MOST DANGEROUS CASE - Running arbitrary command from LLM: " + llm_command)
    os.system(llm_command)  # THIS IS THE MOST DANGEROUS CASE!

def main():
    print("Running examples of safe and unsafe shell command execution...")
    safe_execution_examples()
    unsafe_execution_examples()

if __name__ == "__main__":
    main()