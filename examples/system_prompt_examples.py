"""
Examples of LLM API calls with various system prompt configurations.

This file contains examples of:
1. Missing system prompts
2. Properly used system prompts
3. System instructions misplaced in user messages
4. Correct use of developer role
"""

import openai
from openai import OpenAI


# Example 1: Missing system prompt (will trigger the MissingSystemPromptRule)
def missing_system_prompt():
    client = OpenAI(api_key="YOUR_API_KEY")
    
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": "What are the top 3 programming languages in 2025?"
            }
        ]
    )
    return completion.choices[0].message.content


# Example 2: Properly using system prompt
def correct_system_prompt():
    client = OpenAI(api_key="YOUR_API_KEY")
    
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": "You are a helpful programming assistant that provides factual information about programming languages."
            },
            {
                "role": "user",
                "content": "What are the top 3 programming languages in 2025?"
            }
        ]
    )
    return completion.choices[0].message.content


# Example 3: Misplaced system instructions in user message
def misplaced_system_instructions():
    client = OpenAI(api_key="YOUR_API_KEY")
    
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": "You are a helpful programming assistant that provides factual information. What are the top 3 programming languages in 2025?"
            }
        ]
    )
    return completion.choices[0].message.content


# Example 4: Using developer role (new alternative to system role)
def using_developer_role():
    client = OpenAI(api_key="YOUR_API_KEY")
    
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "developer",
                "content": "Provide factual information about programming languages. Use bullet points when listing items."
            },
            {
                "role": "user",
                "content": "What are the top 3 programming languages in 2025?"
            }
        ]
    )
    return completion.choices[0].message.content


# Example 5: Complex formatting instructions misplaced in user message
def complex_misplaced_instructions():
    client = OpenAI(api_key="YOUR_API_KEY")
    
    user_prompt = """
    You will act as a technical expert on machine learning. 
    
    Format your response using the following structure:
    1. Brief explanation of the concept
    2. Three practical examples
    3. A code snippet if applicable
    
    Now, explain the concept of gradient descent in machine learning.
    """
    
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": user_prompt
            }
        ]
    )
    return completion.choices[0].message.content


# Example 6: Anthropic API with missing system prompt
def anthropic_missing_system():
    import anthropic
    
    client = anthropic.Anthropic(api_key="YOUR_API_KEY")
    
    message = client.messages.create(
        model="claude-3-opus-20240229",
        messages=[
            {
                "role": "user",
                "content": "What's the difference between supervised and unsupervised learning?"
            }
        ]
    )
    return message.content[0].text


# Example 7: Anthropic API with correct system prompt
def anthropic_correct_system():
    import anthropic
    
    client = anthropic.Anthropic(api_key="YOUR_API_KEY")
    
    message = client.messages.create(
        model="claude-3-opus-20240229",
        messages=[
            {
                "role": "system",
                "content": "You are Claude, an AI assistant created by Anthropic to be helpful, harmless, and honest."
            },
            {
                "role": "user", 
                "content": "What's the difference between supervised and unsupervised learning?"
            }
        ]
    )
    return message.content[0].text


if __name__ == "__main__":
    # These function calls are just for demonstration purposes
    # The scanner will analyze the code to find issues without executing it
    pass