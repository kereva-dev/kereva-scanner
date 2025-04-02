"""
This file tests the comment exclusion feature.
"""

import openai

# This line should trigger an unsafe input warning
user_input = input("Enter your question: ")

# This line should be excluded from scanning completely
dangerous_input = input("Enter more: ")  # scanner:ignore

# This line should be excluded from only the chain-unsanitized-input rule
risky_input = input("Enter yet more: ")  # scanner:disable=chain-unsanitized-input

# This line should be excluded from multiple rules
multi_excluded = input("Final input: ")  # scanner:disable=chain-unsanitized-input,prompt-subjective-terms

# These lines should trigger warnings
prompt1 = f"Answer this question: {user_input}"
response1 = openai.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": prompt1}]
)

# These lines should NOT trigger warnings due to the scanner:ignore comment
prompt2 = f"Answer this question: {dangerous_input}"  # scanner:ignore
response2 = openai.chat.completions.create(  # scanner:ignore
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": prompt2}]
)

# This should trigger a warning for subjective terms but not for unsanitized input
prompt3 = f"Give me a good, excellent answer to: {risky_input}"
response3 = openai.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[{"role": "user", "content": prompt3}]
)

# This line uses scanner:disable to disable all rules for this line
exec(response1.choices[0].message.content)  # scanner:disable