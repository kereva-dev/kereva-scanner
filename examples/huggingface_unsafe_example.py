"""
HuggingFace Unsafe Example

This example demonstrates unsafe ways to use HuggingFace models,
which should be detected by our security scanners.
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
import torch
import pickle
import sys

# Example 1: Using trust_remote_code=True (security vulnerability)
def load_model_with_remote_code():
    model_name = "gpt2"  # Replace with any model
    
    # This is unsafe as it allows arbitrary code execution from the model repo
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_name, 
        trust_remote_code=True  # This should be detected as a security issue
    )
    
    return model, tokenizer

# Example 2: Loading unsafe serialized formats
def load_unsafe_serialization():
    # Using pickle format (unsafe)
    with open("model.pkl", "rb") as f:
        model = pickle.load(f)  # This should be detected as a security issue
    
    # Using PyTorch native serialization (unsafe)
    model_state = torch.load("model.pt")  # This should be detected as a security issue
    
    # Specifying pickle format explicitly
    tokenizer = AutoTokenizer.from_pretrained("local_model", format="pickle")  # This should be detected
    
    return model

# Example 3: Loading model from untrusted source with unsafe format
def load_model_from_path():
    # Loading a .bin file (potentially unsafe)
    model = AutoModelForCausalLM.from_pretrained("path/to/pytorch_model.bin")  # This should be detected
    
    # Variable usage - harder to detect but still a concern
    model_path = "model.pt"  # PyTorch format
    model = AutoModelForCausalLM.from_pretrained(model_path)
    
    return model

# Example 4: Unsafe with variables that make detection more complex
def load_with_variable_params():
    model_name = "gpt2"
    trust_code = True  # Variable holding unsafe value
    
    # This should ideally be detected, but might be harder
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=trust_code)
    
    # Creating a params dict - even harder to detect
    params = {
        "trust_remote_code": True,
        "low_cpu_mem_usage": True
    }
    
    # This should ideally be detected, but might be very hard via static analysis
    model = AutoModelForCausalLM.from_pretrained(model_name, **params)
    
    return model, tokenizer

if __name__ == "__main__":
    print("These examples contain security vulnerabilities that should be detected.")
    # Don't actually run these examples