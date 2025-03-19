import ast
import os
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from core.base_visitor import BaseVisitor
from core.ast_utils import (
    extract_string_value, extract_fstring, extract_fstring_vars,
    get_function_name, follow_param_path, is_call_matching,
    variable_name_matches_patterns
)
from core.config import (
    LLM_API_PATTERNS, PROMPT_VARIABLE_PATTERNS
)


@dataclass
class Prompt:
    """Represents an LLM prompt found in code."""
    content: str
    line_number: int
    variable_name: Optional[str] = None
    api_call: Optional[str] = None
    is_template: bool = False
    template_variables: List[str] = None
    
    def __post_init__(self):
        if self.template_variables is None:
            self.template_variables = []
            
    def __str__(self):
        # Ensure the content is converted to a string
        content_str = str(self.content)[:50] if self.content else ""
        return f"Prompt(line={self.line_number}, var={self.variable_name}, content='{content_str}...')"


class PromptExtractor(BaseVisitor):
    """Extracts LLM prompts from Python code by analyzing the AST."""
    
    def __init__(self, context=None):
        super().__init__(context)
        self.prompts = []
        
    def visit_Assign(self, node):
        """Track variable assignments with improved handling."""
        # Get the variable name
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            
            # Check if the variable name suggests it's a prompt
            var_name_suggests_prompt = variable_name_matches_patterns(var_name, PROMPT_VARIABLE_PATTERNS)
            
            # Handle direct string assignment
            if isinstance(node.value, ast.Str) or (hasattr(ast, 'Constant') and isinstance(node.value, ast.Constant) and isinstance(getattr(node.value, 'value', None), str)):
                content = extract_string_value(node.value)
                is_prompt = var_name_suggests_prompt or self._looks_like_prompt(content)
                
                self.variables[var_name] = {
                    "value": content,
                    "line": node.lineno,
                    "is_prompt": is_prompt,
                    "is_template": False
                }
                
                if is_prompt:
                    self.prompts.append(Prompt(
                        content=content,
                        line_number=node.lineno,
                        variable_name=var_name,
                        is_template=False
                    ))
            
            # Handle dictionary assignment with prompt fields
            elif isinstance(node.value, ast.Dict):
                if os.environ.get('DEBUG') == "1":
                    print(f"  - Analyzing dictionary assignment to {var_name}")
                    
                # Look for fields that could contain prompts
                prompt_field_names = ["prompt", "text", "content", "message", "query", "question", "instructions"]
                
                # Look through keys in the dictionary
                for i, key_node in enumerate(node.value.keys):
                    if i < len(node.value.values):
                        # Extract the key name if it's a string
                        key_name = None
                        if isinstance(key_node, ast.Str):
                            key_name = key_node.s
                        elif hasattr(ast, 'Constant') and isinstance(key_node, ast.Constant):
                            if isinstance(key_node.value, str):
                                key_name = key_node.value
                        
                        # If the key matches a prompt field, process the value
                        if key_name and any(field == key_name.lower() for field in prompt_field_names):
                            value_node = node.value.values[i]
                            # Extract the string value if available
                            content = extract_string_value(value_node)
                            
                            if os.environ.get('DEBUG') == "1":
                                print(f"    - Found prompt field: '{key_name}' with content: '{content[:30] if content else None}...'")
                                
                            if content and self._looks_like_prompt(content):
                                self.prompts.append(Prompt(
                                    content=content,
                                    line_number=node.lineno,
                                    variable_name=f"{var_name}.{key_name}",
                                    is_template=isinstance(value_node, ast.JoinedStr),
                                    template_variables=extract_fstring_vars(value_node) if isinstance(value_node, ast.JoinedStr) else []
                                ))
                                
                                if os.environ.get('DEBUG') == "1":
                                    print(f"    - Added prompt from dictionary field: {var_name}.{key_name}")
                    
            # Handle f-strings (JoinedStr)
            elif isinstance(node.value, ast.JoinedStr):
                template_str = extract_fstring(node.value)
                template_vars = extract_fstring_vars(node.value)
                is_prompt = var_name_suggests_prompt or self._looks_like_prompt(template_str)
                
                # Ensure we store a string representation of the template
                template_str_value = str(template_str) if template_str is not None else ""
                
                # Store the raw node for downstream use
                self.variables[var_name] = {
                    "node": node.value,
                    "value": template_str_value,  # Store as string, not the AST node
                    "line": node.lineno,
                    "is_prompt": is_prompt,
                    "is_template": True,
                    "template_vars": template_vars
                }
                
                if is_prompt:
                    self.prompts.append(Prompt(
                        content=template_str_value,  # Pass as string
                        line_number=node.lineno,
                        variable_name=var_name,
                        is_template=True,
                        template_variables=template_vars
                    ))
                    
                    # Ensure the object ref is not stored directly for JoinedStr
                    if isinstance(self.prompts[-1].content, ast.AST):
                        self.prompts[-1].content = str(self.prompts[-1].content)
                    
            # Handle string concatenation (BinOp with + operator)
            elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                concatenated_str = extract_string_value(node.value)
                if concatenated_str:
                    is_prompt = var_name_suggests_prompt or self._looks_like_prompt(concatenated_str)
                    
                    self.variables[var_name] = {
                        "value": concatenated_str,
                        "line": node.lineno,
                        "is_prompt": is_prompt,
                        "is_template": False
                    }
                    
                    if is_prompt:
                        self.prompts.append(Prompt(
                            content=concatenated_str,
                            line_number=node.lineno,
                            variable_name=var_name,
                            is_template=False
                        ))
        
        # Continue visiting child nodes
        super().visit_Assign(node)
    
    def visit_AugAssign(self, node):
        """Track augmented assignments like var += "string"."""
        if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            var_name = node.target.id
            
            # If we're adding to a variable that might be a prompt
            if var_name in self.variables:
                # Extract the string being added
                added_str = extract_string_value(node.value)
                if added_str:
                    # Debug info
                    if os.environ.get('DEBUG') == "1":
                        print(f"AugAssign: {var_name} += '{added_str}'")
                        print(f"Current value type: {type(self.variables[var_name]['value'])}")
                        print(f"Current value: {self.variables[var_name]['value']}")
                    
                    # Update the variable's value - handle the case where it might be a JoinedStr
                    if "node" in self.variables[var_name] and isinstance(self.variables[var_name]["node"], ast.JoinedStr):
                        # For JoinedStr nodes, get the string representation fresh from the extracted f-string
                        content = extract_fstring(self.variables[var_name]["node"])
                        self.variables[var_name]["value"] = str(content) + added_str
                    elif isinstance(self.variables[var_name]["value"], str):
                        self.variables[var_name]["value"] += added_str
                    else:
                        # If it's not a string (could be a JoinedStr or AST node), convert to string first
                        self.variables[var_name]["value"] = str(self.variables[var_name]["value"]) + added_str
                    
                    # Check if it now looks like a prompt
                    combined_str = self.variables[var_name]["value"]
                    if not self.variables[var_name].get("is_prompt", False) and self._looks_like_prompt(combined_str):
                        self.variables[var_name]["is_prompt"] = True
                        new_prompt = Prompt(
                            content=combined_str,
                            line_number=self.variables[var_name]["line"],
                            variable_name=var_name,
                            is_template=self.variables[var_name].get("is_template", False)
                        )
                        
                        # Ensure we don't store AST nodes directly
                        if isinstance(new_prompt.content, ast.AST):
                            new_prompt.content = str(new_prompt.content)
                            
                        self.prompts.append(new_prompt)
                    # Update the corresponding prompt if it exists
                    else:
                        for prompt in self.prompts:
                            if prompt.variable_name == var_name:
                                prompt.content = combined_str
                                break
            # If this is a new variable that looks like it might be a prompt
            elif variable_name_matches_patterns(var_name, PROMPT_VARIABLE_PATTERNS):
                added_str = extract_string_value(node.value)
                if added_str:
                    is_prompt = self._looks_like_prompt(added_str)
                    self.variables[var_name] = {
                        "value": added_str,
                        "line": node.lineno,
                        "is_prompt": is_prompt,
                        "is_template": False
                    }
                    
                    if is_prompt:
                        new_prompt = Prompt(
                            content=added_str,
                            line_number=node.lineno,
                            variable_name=var_name,
                            is_template=False
                        )
                        
                        # Ensure we don't store AST nodes directly
                        if isinstance(new_prompt.content, ast.AST):
                            new_prompt.content = str(new_prompt.content)
                            
                        self.prompts.append(new_prompt)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Track function calls and identify LLM API calls."""
        func_name = get_function_name(node)
        if os.environ.get('DEBUG') == "1":
            print(f"\n  PromptExtractor.visit_Call: {func_name}")
        
        # Check if this is a known LLM API call
        if is_call_matching(node, LLM_API_PATTERNS):
            if os.environ.get('DEBUG') == "1":
                print(f"    - Found known LLM API call: {func_name}")
            
            # Extract prompt from potential parameters
            for param_path in [["messages", 0, "content"], ["prompt"], ["query"], ["question"]]:
                prompt_node = follow_param_path(node, param_path)
                if prompt_node:
                    if os.environ.get('DEBUG') == "1":
                        print(f"    - Found potential prompt node via path: {param_path}")
                    self._process_prompt_node(prompt_node, func_name)
                    break
            
            # Also check first positional argument
            if node.args and not prompt_node:
                self._process_prompt_node(node.args[0], func_name)
        
        # Check for common patterns in function calls that might involve prompts
        for kw in node.keywords:
            if kw.arg in ["text", "prompt", "query", "instructions", "system_message", "user_message"]:
                if os.environ.get('DEBUG') == "1":
                    print(f"    - Found keyword argument '{kw.arg}' that suggests prompt")
                self._process_prompt_node(kw.value, f"{func_name}({kw.arg})")
        
        # Continue visiting child nodes
        super().visit_Call(node)
    
    def _process_prompt_node(self, node, api_call):
        """Process a node that contains a prompt."""
        if os.environ.get('DEBUG') == "1":
            print(f"\n  PromptExtractor._process_prompt_node called with node type: {type(node).__name__}")
        
        # Handle direct string literal
        content = extract_string_value(node)
        if content:
            if os.environ.get('DEBUG') == "1":
                print(f"    - Extracted content: '{content[:50]}...'")
            if self._looks_like_prompt(content):
                is_template = isinstance(node, ast.JoinedStr)
                template_vars = extract_fstring_vars(node) if is_template else []
                
                self.prompts.append(Prompt(
                    content=content,
                    line_number=getattr(node, 'lineno', 0),
                    api_call=api_call,
                    is_template=is_template,
                    template_variables=template_vars
                ))
                if os.environ.get('DEBUG') == "1":
                    print(f"    - Prompt added")
        
        # Handle variable reference
        elif isinstance(node, ast.Name):
            var_name = node.id
            if os.environ.get('DEBUG') == "1":
                print(f"    - Variable reference: {var_name}")
            if var_name in self.variables:
                if os.environ.get('DEBUG') == "1":
                    print(f"    - Found variable in tracked variables")
                var_info = self.variables[var_name]
                
                # Special handling for dictionaries that might contain prompts
                if "node" in var_info and hasattr(var_info["node"], "value") and isinstance(var_info["node"].value, ast.Dict):
                    if os.environ.get('DEBUG') == "1":
                        print(f"    - Variable is a dictionary, checking for prompt fields")
                        
                    # Look for fields that could contain prompts
                    prompt_field_names = ["prompt", "text", "content", "message", "query", "question", "instructions"]
                    
                    # Look through keys in the dictionary
                    if hasattr(var_info["node"].value, "keys") and hasattr(var_info["node"].value, "values"):
                        for i, key_node in enumerate(var_info["node"].value.keys):
                            if i < len(var_info["node"].value.values):
                                # Extract the key name if it's a string
                                key_name = None
                                if isinstance(key_node, ast.Str):
                                    key_name = key_node.s
                                elif hasattr(ast, 'Constant') and isinstance(key_node, ast.Constant):
                                    if isinstance(key_node.value, str):
                                        key_name = key_node.value
                                
                                # If the key matches a prompt field, process the value
                                if key_name and any(field == key_name.lower() for field in prompt_field_names):
                                    value_node = var_info["node"].value.values[i]
                                    # Extract the string value if available
                                    content = extract_string_value(value_node)
                                    
                                    if os.environ.get('DEBUG') == "1":
                                        print(f"    - Found prompt field: '{key_name}' with content: '{content[:30]}...'")
                                        
                                    if content and self._looks_like_prompt(content):
                                        self.prompts.append(Prompt(
                                            content=content,
                                            line_number=var_info["line"],
                                            variable_name=f"{var_name}.{key_name}",
                                            api_call=api_call,
                                            is_template=isinstance(value_node, ast.JoinedStr),
                                            template_variables=extract_fstring_vars(value_node) if isinstance(value_node, ast.JoinedStr) else []
                                        ))
                                        
                                        if os.environ.get('DEBUG') == "1":
                                            print(f"    - Added prompt from dictionary field: {var_name}.{key_name}")
                                        
                # For regular string variables
                else:
                    # Extract the string value if it exists
                    value_to_check = None
                    
                    if "string_value" in var_info and var_info["string_value"]:
                        # If a string value was extracted, use that
                        value_to_check = var_info["string_value"]
                    elif "value" in var_info and isinstance(var_info["value"], str):
                        value_to_check = var_info["value"]
                        
                    # Only add to prompts if we have a valid string content
                    if value_to_check:
                        self.prompts.append(Prompt(
                            content=value_to_check,
                            line_number=var_info["line"],
                            variable_name=var_name,
                            api_call=api_call,
                            is_template=var_info.get("is_template", False),
                            template_variables=var_info.get("template_vars", [])
                        ))
                if os.environ.get('DEBUG') == "1":
                    print(f"    - Prompt added")
            elif os.environ.get('DEBUG') == "1":
                print(f"    - Variable not found in tracked variables")
        
        # Handle string formatting: var.format(...)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if os.environ.get('DEBUG') == "1":
                print(f"    - String formatting with .format()")
            if isinstance(node.func.value, ast.Name):
                var_name = node.func.value.id
                if os.environ.get('DEBUG') == "1":
                    print(f"    - Format base variable: {var_name}")
                if var_name in self.variables:
                    if os.environ.get('DEBUG') == "1":
                        print(f"    - Found variable in tracked variables")
                    var_info = self.variables[var_name]
                    self.prompts.append(Prompt(
                        content=var_info["value"],
                        line_number=var_info["line"],
                        variable_name=var_name,
                        api_call=api_call,
                        is_template=True
                    ))
                    if os.environ.get('DEBUG') == "1":
                        print(f"    - Prompt added")
                elif os.environ.get('DEBUG') == "1":
                    print(f"    - Variable not found in tracked variables")
        elif os.environ.get('DEBUG') == "1":
            print(f"    - Unhandled node type: {type(node).__name__}")
    
    def _looks_like_prompt(self, text):
        """Heuristic to determine if a string looks like a prompt."""
        if not isinstance(text, str):
            return False
            
        # Too short strings are unlikely to be prompts
        if len(text) < 10:
            return False
            
        # Skip strings that are likely not prompts
        non_prompt_indicators = [
            "http://", "https://",
            ".py", ".js", ".ts", ".html", ".css",  # File extensions
            "import ", "from ",  # Code snippets
            "def ", "class ",  # Code snippets
        ]
        
        for indicator in non_prompt_indicators:
            if indicator in text:
                return False
                
        # Check for code snippet patterns that are NOT prompts
        code_indicators = ["def ", "class ", "import ", "from ", " = ", "+=", "-=", "return ", "raise "]
        code_line_count = sum(1 for line in text.split("\n") if any(indicator in line for indicator in code_indicators))
        total_lines = text.count("\n") + 1
        # If more than 40% of lines look like code, it's probably not a prompt
        if total_lines > 3 and code_line_count / total_lines > 0.4:
            return False
        
        # Check for common prompt indicators
        prompt_indicators = [
            "answer", "question", "respond", "write", "generate", "create", 
            "explain", "summarize", "analyze", "assess", "evaluate", "provide",
            "<prompt>", "<question>", "<context>", "system:", "user:", 
            "assistant:", "instructions:", "description:", "output:", 
            "please", "task", "bullet points", "score", "json"
        ]
        
        # Check for structural indicators (common in prompts)
        structural_indicators = [
            ":\n", "```", "- ", "1. ", "•", "Step ", 
            "\n\n", "Input:", "Output:"
        ]
        
        text_lower = text.lower()
        
        # Check for question marks, which often indicate prompts
        has_question_mark = "?" in text
        
        # Check for multiple lines, which is common in prompts
        is_multiline = "\n" in text
        
        # Check for imperative verbs at the beginning of sentences
        imperative_start = any(text_lower.startswith(verb) or 
                              text_lower.startswith(f"\n{verb}") for verb in 
                              ["write", "create", "generate", "list", "explain", 
                               "describe", "summarize", "analyze", "evaluate", "provide"])
        
        # Content indicators
        has_prompt_indicators = any(indicator in text_lower for indicator in prompt_indicators)
        has_structural_indicators = any(indicator in text for indicator in structural_indicators)
        
        # Check for LLM API context in parent node
        is_in_llm_context = self._is_in_llm_context()
        
        # Combine all signals - more stringent detection to reduce false positives
        return (is_in_llm_context or
                (has_prompt_indicators and (is_multiline or has_question_mark)) or 
                (has_structural_indicators and is_multiline) or 
                (imperative_start and is_multiline) or 
                (has_question_mark and is_multiline and len(text) > 100))
                
    def _is_in_llm_context(self):
        """Check if the current context suggests we're in LLM-related code.
        This helps determine if strings are more likely to be prompts.
        """
        # This is a placeholder for now - in a real implementation, this would
        # look at the current function name, class name, and other context clues
        # to determine if we're in an LLM-related context
        return False
        
    def extract_messages_arrays(self) -> List[Dict[str, Any]]:
        """
        Extract message arrays from LLM API calls.
        
        Returns:
            List of dictionaries containing message arrays with role/content information
        """
        message_arrays = []
        
        # Function to extract message array from an API call
        def process_api_call(node, api_call_name=None):
            if not isinstance(node, ast.Call):
                return None
                
            # Look for 'messages' parameter
            for kw in node.keywords:
                if kw.arg == "messages" and isinstance(kw.value, ast.List):
                    messages = []
                    
                    # Process each message in the array
                    for msg_node in kw.value.elts:
                        if not isinstance(msg_node, ast.Dict):
                            continue
                            
                        # Extract role and content from the message dictionary
                        msg_data = {}
                        
                        for i, key_node in enumerate(msg_node.keys):
                            key_str = None
                            
                            # Extract key string
                            if isinstance(key_node, ast.Str):
                                key_str = key_node.s
                            elif hasattr(ast, 'Constant') and isinstance(key_node, ast.Constant):
                                key_str = key_node.value if isinstance(key_node.value, str) else None
                                
                            if key_str and i < len(msg_node.values):
                                value_node = msg_node.values[i]
                                
                                # Extract value based on node type
                                if key_str == "role":
                                    # For role, extract string value
                                    if isinstance(value_node, ast.Str):
                                        msg_data["role"] = value_node.s
                                    elif hasattr(ast, 'Constant') and isinstance(value_node, ast.Constant):
                                        msg_data["role"] = value_node.value if isinstance(value_node.value, str) else None
                                
                                elif key_str == "content":
                                    # For content, handle different node types
                                    content_value = extract_string_value(value_node)
                                    if content_value is not None:
                                        msg_data["content"] = content_value
                                    # If it's a variable name, store it with special handling
                                    elif isinstance(value_node, ast.Name):
                                        var_name = value_node.id
                                        if var_name in self.variables:
                                            var_info = self.variables.get(var_name, {})
                                            msg_data["content"] = var_info.get("value", f"VARIABLE:{var_name}")
                                        else:
                                            msg_data["content"] = f"VARIABLE:{var_name}"
                                    # If all else fails, store the node itself for inspection
                                    else:
                                        msg_data["content"] = extract_string_value(value_node) or str(value_node)
                                            
                        if msg_data:
                            messages.append(msg_data)
                    
                    # If we found messages, create a message array entry
                    if messages:
                        line_number = getattr(node, "lineno", 0)
                        message_arrays.append({
                            "messages": messages,
                            "line": line_number,
                            "api_call": api_call_name or self._get_function_name(node)
                        })
        
        # Visitor to find and process API calls
        class MessageArrayVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                function_name = get_function_name(node)
                
                # Check if this is a known LLM API call
                if is_call_matching(node, LLM_API_PATTERNS):
                    process_api_call(node, function_name)
                
                self.generic_visit(node)
        
        # Create a visitor and apply it to the same root node we're analyzing
        if hasattr(self, 'context') and 'tree' in self.context:
            MessageArrayVisitor().visit(self.context['tree'])
        
        return message_arrays
        
    def _get_function_name(self, node):
        """Get the function name from a call node."""
        if isinstance(node.func, ast.Attribute):
            attr_chain = []
            current = node.func
            
            while isinstance(current, ast.Attribute):
                attr_chain.append(current.attr)
                current = current.value
                
            if isinstance(current, ast.Name):
                attr_chain.append(current.id)
                attr_chain.reverse()
                return ".".join(attr_chain)
        
        return "unknown"