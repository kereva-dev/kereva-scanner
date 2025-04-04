"""
Simple example file with a direct LLM output execution vulnerability.
"""

import os
import subprocess
import openai

# Simple LLM call that returns a command string
def get_command_from_llm():
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Suggest a unix command"}]
    )
    llm_command = response.choices[0].message.content
    return llm_command

# VULNERABLE: Direct execution of LLM output - this should be detected
def vulnerable_function():
    command = get_command_from_llm()
    os.system(command)  # This is highly dangerous!
    
    # Also test subprocess with direct LLM output
    subprocess.run(command, shell=True)

# VULNERABLE: Direct execution of LLM output in a more realistic scenario 
def realistic_example():
    # Get LLM to suggest a command for data processing
    prompt = "Can you suggest a command to process the data in data.csv?"
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    # Extract and execute command
    suggested_command = response.choices[0].message.content
    print(f"Executing: {suggested_command}")
    os.system(suggested_command)  # UNSAFE direct execution

if __name__ == "__main__":
    vulnerable_function()
    realistic_example()