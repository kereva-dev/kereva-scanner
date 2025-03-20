"""
HuggingFace Example

This example demonstrates various ways to use HuggingFace models,
including potential security issues that should be detected by our scanner.
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline, TextGenerationPipeline
from huggingface_hub import InferenceClient, HfApi
import torch
import sys

# Example 1: Basic model loading and generation
def basic_generation():
    model_name = "gpt2"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name)
    
    # Safe usage - hardcoded prompt
    input_text = "Once upon a time"
    inputs = tokenizer(input_text, return_tensors="pt")
    output = model.generate(**inputs, max_length=50)
    print(tokenizer.decode(output[0], skip_special_tokens=True))

# Example 2: Using the pipeline API with user input (potentially unsafe)
def pipeline_generation(user_input=None):
    if user_input is None:
        user_input = "Tell me a story about"
    
    # Potentially unsafe - user input flows directly to model
    generator = pipeline("text-generation", model="gpt2")
    result = generator(user_input, max_length=50)
    print(result[0]["generated_text"])

# Example 3: Using HuggingFace Inference API with user arguments
def inference_api_example():
    client = InferenceClient(model="gpt2")
    
    # Potentially unsafe - command line args flow to model
    query = sys.argv[1] if len(sys.argv) > 1 else "Hello, how are you?"
    
    # This should be detected as unsafe
    response = client.text_generation(query)
    print(response)

# Example 4: TextGenerationPipeline with direct call
def pipeline_direct_call():
    tokenizer = AutoTokenizer.from_pretrained("gpt2")
    model = AutoModelForCausalLM.from_pretrained("gpt2")
    
    text_generator = TextGenerationPipeline(model=model, tokenizer=tokenizer)
    
    # Unsafe - user message flows directly to model
    user_message = input("Enter your message: ")
    result = text_generator(user_message)
    print(result[0]["generated_text"])

if __name__ == "__main__":
    basic_generation()
    pipeline_generation("Hello, my name is")
    inference_api_example()
    # Commented out as it requires user input
    # pipeline_direct_call()