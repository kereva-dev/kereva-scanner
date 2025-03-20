"""
HuggingFace Secure Example

This example demonstrates secure ways to use HuggingFace models,
with proper input sanitization to prevent prompt injection.
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline, TextGenerationPipeline
from huggingface_hub import InferenceClient
import torch
import sys
import re

# List of allowed inputs for validation
ALLOWED_INPUTS = [
    "Tell me a story about a robot",
    "Write a poem about nature",
    "Explain quantum physics",
    "Describe the solar system"
]

# Example 1: Using allow-list approach for input validation
def secure_pipeline_generation(user_input):
    # Validate input against allowlist
    if user_input not in ALLOWED_INPUTS:
        return "Input not allowed. Please choose from the approved prompts."
    
    # After validation, input is considered safe
    generator = pipeline("text-generation", model="gpt2")
    result = generator(user_input, max_length=50)
    return result[0]["generated_text"]

# Example 2: Using regex pattern matching for sanitization
def secure_model_generation(user_input):
    # Define pattern for allowed inputs
    pattern = r'^[a-zA-Z0-9 .,!?]+$'
    
    # Validate input with pattern
    if not re.match(pattern, user_input):
        return "Input contains disallowed characters"
    
    # Sanitize further by ensuring reasonable length
    if len(user_input) > 100:
        return "Input exceeds maximum allowed length"
    
    # After validation, proceed with generation
    tokenizer = AutoTokenizer.from_pretrained("gpt2")
    model = AutoModelForCausalLM.from_pretrained("gpt2")
    inputs = tokenizer(user_input, return_tensors="pt")
    output = model.generate(**inputs, max_length=50)
    return tokenizer.decode(output[0], skip_special_tokens=True)

# Example 3: Command-line input with sanitization
def secure_inference_api(args):
    # Validate command-line arguments with sanitization
    if len(args) < 2:
        return "No input provided"
    
    # Get input from command line
    query = args[1]
    
    # Validate against allowlist
    if query not in ALLOWED_INPUTS:
        return "Command-line input not in allowed list"
    
    # After validation, proceed with API call
    client = InferenceClient(model="gpt2")
    response = client.text_generation(query)
    return response

if __name__ == "__main__":
    # Example usage
    print("Allow-list example:")
    result1 = secure_pipeline_generation("Tell me a story about a robot")
    print(result1)
    
    print("\nPattern matching example:")
    result2 = secure_model_generation("Hello world")
    print(result2)
    
    print("\nCommand-line argument example (if provided):")
    message = secure_inference_api(sys.argv if len(sys.argv) > 1 else ["script"])
    print(message)