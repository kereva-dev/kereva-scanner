"""
HuggingFace Safe Alternatives Example

This example demonstrates safer alternatives to the security vulnerabilities
detected by our HuggingFace security scanners.
"""

from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from safetensors.torch import save_file, load_file
import os

# Example 1: Safe model loading without trust_remote_code
def load_model_safely():
    model_name = "gpt2"  # Replace with any model
    
    # This is safe - doesn't use trust_remote_code
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name)
    
    # Or explicitly disable it
    model = AutoModelForCausalLM.from_pretrained(
        model_name, 
        trust_remote_code=False  # Explicitly disabled
    )
    
    return model, tokenizer

# Example 2: Using safetensors instead of unsafe formats
def use_safe_serialization():
    model_name = "gpt2"
    
    # Load model
    model = AutoModelForCausalLM.from_pretrained(model_name)
    
    # Save using safetensors format
    model.save_pretrained("safe_model", safe_serialization=True)
    
    # Load with safetensors format
    safe_model = AutoModelForCausalLM.from_pretrained(
        "safe_model", 
        format="safetensors"  # Explicitly request safetensors format
    )
    
    return safe_model

# Example 3: Converting existing state_dict to safetensors
def convert_to_safetensors():
    model_name = "gpt2"
    
    # Load model
    model = AutoModelForCausalLM.from_pretrained(model_name)
    
    # Get state dict
    state_dict = model.state_dict()
    
    # Save using safetensors
    os.makedirs("safe_model", exist_ok=True)
    save_file(state_dict, "safe_model/model.safetensors")
    
    # Load directly with safetensors
    loaded_state_dict = load_file("safe_model/model.safetensors")
    
    return loaded_state_dict

# Example 4: Using specific revision hashes for trusted code
def use_revision_hash():
    model_name = "gpt2"
    revision = "e7da7f221d5bf496a48136c0cd264e630fe9fcc8"  # Example hash
    
    # Load specific version of the model
    tokenizer = AutoTokenizer.from_pretrained(model_name, revision=revision)
    model = AutoModelForCausalLM.from_pretrained(model_name, revision=revision)
    
    return model, tokenizer

if __name__ == "__main__":
    print("These examples demonstrate safe alternatives to common HuggingFace security issues.")