import ast
import os
import re
from typing import Optional, Dict, Any, List, Set
from rules.prompt.xml_tags.abstract_rule import AbstractXMLTagRule
from core.issue import Issue


class XMLTagRule(AbstractXMLTagRule):
    """Rule to check if user input is enclosed in XML tags.
    
    This implementation combines both the direct AST scanning approach 
    and the prompt content analysis to provide comprehensive detection
    of unprotected user input in LLM prompts.
    """
    
    def __init__(self):
        super().__init__(
            rule_id="prompt-xml-tags",
            description="User input should be enclosed in XML tags for better prompt safety",
            severity="medium"
        )
        self.suggestion = "Enclose user input in XML tags, e.g., <user_input>{input_var}</user_input>"
        
        # Variables that are commonly recognized as external user input
        self.external_input_patterns = [
            "user_input", "query", "question", "prompt", "request", 
            "user_message", "input", "user_query", "message", "text",
            "customer_request", "client_input", "human_input"
        ]
        
        # Variables that are typically safe internal data (not user input)
        self.safe_internal_patterns = [
            "datetime", "date", "time", "timestamp", "now", "today",
            "system_message", "instructions", "settings", "config",
            "api_key", "version", "model", "temperature", "max_tokens",
            "system_prompt", "context", "format", "style", "prefix", 
            "suffix", "delimiter", "separator", "template", "response_format",
            "docs", "examples"
        ]
    
    def _check_ast_node(self, node: ast.AST, context: Dict[str, Any]) -> Optional[Issue]:
        """Check an AST node directly for XML tag issues."""
        
        # Extract all string variables that might contain user input
        variables = self._extract_variables(node)
        
        # Find LLM API calls that might use these variables
        api_calls = self._extract_api_calls(node)
        
        # Check each API call for unsafe usage of user input
        for api_call in api_calls:
            unsafe_inputs = self._check_api_call(api_call, variables)
            if unsafe_inputs:
                # Get API call information for better error context
                func_name = self._get_function_name(api_call)
                
                # Create more detailed issue with call information
                return self._create_issue(
                    api_call, 
                    context, 
                    unwrapped_vars=unsafe_inputs,
                    custom_message=f"User input being passed to LLM API call `{func_name}` should be enclosed in XML tags",
                    additional_context={
                        "api_call": func_name,
                        "variable_definitions": {
                            var: variables.get(var, {}).get("line", 0) for var in unsafe_inputs
                        }
                    }
                )
                
        return None
        
    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from call node for better error reporting."""
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
            
        return "API call"
    
    def _check_prompt_content(self, node_info: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check extracted prompt content for XML tag issues."""
        content = node_info['content']
        line = node_info.get('line', 0)
        is_template = node_info.get('is_template', False)
        template_variables = node_info.get('template_variables', [])
        
        # Use a uniform approach - we only need to check the content type once
        # If it's not a string, we can't analyze it for XML tags
        if not isinstance(content, str):
            return None
            
        # Identify external inputs in the prompt
        external_inputs = self._identify_external_inputs(content, template_variables)
        
        # If there are no external inputs, no need to check for XML tags
        if not external_inputs:
            return None
            
        # Check if all external inputs are properly enclosed in XML tags
        unwrapped_vars = []
        var_line_map = {}
        
        for var in external_inputs:
            if not self._is_variable_wrapped_in_xml(content, var):
                unwrapped_vars.append(var)
                # Find the actual line number for this variable in the content if it's multiline
                var_line_map[var] = self._find_var_line_offset(content, var, line)
        
        if unwrapped_vars:
            # Create a mock node with line number for issue reporting
            class MockNode:
                def __init__(self, line):
                    self.lineno = line
                    self.col_offset = 0
            
            # If we have a single variable, use its detected line number
            if len(unwrapped_vars) == 1 and var_line_map[unwrapped_vars[0]] > 0:
                mock_node = MockNode(var_line_map[unwrapped_vars[0]])
            else:
                mock_node = MockNode(line)
                
            return self._create_issue(
                mock_node, 
                context, 
                unwrapped_vars=unwrapped_vars,
                additional_context={"variable_locations": var_line_map}
            )
        
        return None
    
    def _find_var_line_offset(self, content: str, var: str, base_line: int) -> int:
        """Find the actual line number for a variable in multiline content."""
        if not content or "\n" not in content:
            return base_line
        
        var_pattern = f"{{{var}}}"
        lines = content.split("\n")
        
        for i, line_content in enumerate(lines):
            if var_pattern in line_content:
                return base_line + i  # Add the offset to the base line number
        
        # If not found, return the base line number
        return base_line
    
    def _extract_variables(self, node: ast.AST) -> Dict[str, Dict[str, Any]]:
        """Extract variables that might contain user input from AST."""
        variables = {}
        
        class VariableVisitor(ast.NodeVisitor):
            def visit_Assign(self, node):
                # Check for string assignments that might be user input
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                    var_lower = var_name.lower()
                    
                    # Check if the variable name suggests it's external input
                    is_external = (any(pattern in var_lower for pattern in self.external_input_patterns) and 
                                  not any(pattern in var_lower for pattern in self.safe_internal_patterns))
                    
                    # Record the variable
                    if is_external:
                        variables[var_name] = {
                            "line": node.lineno,
                            "is_external": True
                        }
                
                self.generic_visit(node)
                
        visitor = VariableVisitor()
        visitor.external_input_patterns = self.external_input_patterns
        visitor.safe_internal_patterns = self.safe_internal_patterns
        visitor.visit(node)
        return variables
    
    def _extract_api_calls(self, node: ast.AST) -> List[ast.Call]:
        """Extract LLM API calls from the AST."""
        api_calls = []
        
        class APICallVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                # Check for OpenAI and other LLM API calls
                if isinstance(node.func, ast.Attribute):
                    attr_chain = []
                    current = node.func
                    
                    while isinstance(current, ast.Attribute):
                        attr_chain.append(current.attr)
                        current = current.value
                    
                    if isinstance(current, ast.Name):
                        attr_chain.append(current.id)
                        attr_chain.reverse()
                        
                        func_name = ".".join(attr_chain)
                        
                        # Check for common LLM API patterns
                        llm_api_patterns = [
                            "openai.chat.completions.create",
                            "openai.ChatCompletion.create",
                            "anthropic.Anthropic().messages.create",
                            "client.chat.completions.create"
                        ]
                        
                        if any(pattern in func_name for pattern in llm_api_patterns):
                            api_calls.append(node)
                
                self.generic_visit(node)
        
        APICallVisitor().visit(node)
        return api_calls
    
    def _check_api_call(self, call_node: ast.Call, variables: Dict[str, Dict[str, Any]]) -> List[str]:
        """Check if an API call uses external input without XML tags."""
        unsafe_inputs = []
        
        # Check if the call has a 'messages' parameter
        for kw in call_node.keywords:
            if kw.arg == "messages" and isinstance(kw.value, ast.List):
                # Check messages for user inputs without proper XML tags
                for i, elt in enumerate(kw.value.elts):
                    if isinstance(elt, ast.Dict):
                        # Look for message dictionaries
                        role = None
                        content = None
                        content_node = None
                        
                        # Extract role and content
                        for j in range(len(elt.keys)):
                            key = elt.keys[j]
                            if isinstance(key, ast.Str) or (hasattr(ast, 'Constant') and isinstance(key, ast.Constant)):
                                key_str = key.s if hasattr(key, 's') else key.value
                                
                                if key_str == "role":
                                    value = elt.values[j]
                                    if isinstance(value, ast.Str) or (hasattr(ast, 'Constant') and isinstance(value, ast.Constant)):
                                        role = value.s if hasattr(value, 's') else value.value
                                
                                elif key_str == "content":
                                    content_node = elt.values[j]
                                    
                                    # Direct string
                                    if isinstance(content_node, ast.Str) or (hasattr(ast, 'Constant') and isinstance(content_node, ast.Constant)):
                                        content = content_node.s if hasattr(content_node, 's') else content_node.value
                                    
                                    # Variable reference
                                    elif isinstance(content_node, ast.Name):
                                        var_name = content_node.id
                                        if var_name in variables and variables[var_name]["is_external"]:
                                            unsafe_inputs.append(var_name)
                                    
                                    # f-string
                                    elif isinstance(content_node, ast.JoinedStr):
                                        # Check for variables in f-string
                                        for value in content_node.values:
                                            if isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                                                var_name = value.value.id
                                                if var_name in variables and variables[var_name]["is_external"]:
                                                    # Check if it's wrapped in XML tags
                                                    xml_wrapped = self._check_fstring_xml_tags(content_node, var_name)
                                                    if not xml_wrapped:
                                                        unsafe_inputs.append(var_name)
        
        return unsafe_inputs
    
    def _check_fstring_xml_tags(self, fstring_node: ast.JoinedStr, var_name: str) -> bool:
        """Check if a variable in an f-string is wrapped in XML tags."""
        # Convert f-string to a string representation
        parts = []
        for value in fstring_node.values:
            if isinstance(value, ast.Str) or (hasattr(ast, 'Constant') and isinstance(value, ast.Constant)):
                parts.append(value.s if hasattr(value, 's') else value.value)
            elif isinstance(value, ast.FormattedValue):
                if isinstance(value.value, ast.Name):
                    parts.append(f"{{{value.value.id}}}")
        
        fstring_repr = "".join(parts)
        
        # Check for XML tag patterns around the variable
        var_pattern = f"{{{var_name}}}"
        return self._is_variable_wrapped_in_xml(fstring_repr, var_name)
    
    def _identify_external_inputs(self, content, template_variables: List[str]) -> Set[str]:
        """Identify variables in the prompt that likely represent external user input."""
        # Check if content is a string - we can't analyze non-string content
        if not isinstance(content, str):
            return set()
            
        # Debug output for the content and variables
        if os.environ.get('DEBUG') == "1":
            print(f"\n_identify_external_inputs:")
            print(f"  Content: '{content}'")
            print(f"  Template vars: {template_variables}")
        
        external_inputs = set()
        
        # Check each template variable to see if it looks like external input
        for var in template_variables:
            var_lower = var.lower()
            
            # Check if the variable matches external input patterns
            if any(pattern in var_lower for pattern in self.external_input_patterns):
                # Make sure it's not a safe internal variable
                if not any(safe_pattern in var_lower for safe_pattern in self.safe_internal_patterns):
                    external_inputs.add(var)
                    if os.environ.get('DEBUG') == "1":
                        print(f"  Found external input variable: {var}")
        
        # Look for patterns in string formatting that aren't in template_variables
        # This helps catch .format() calls and other formatting methods
        format_vars = self._extract_format_vars(content)
        for var in format_vars:
            var_lower = var.lower()
            
            # For format variables, we consider two approaches:
            # 1. If it explicitly matches an external input pattern, flag it 
            # 2. If it doesn't match any safe internal pattern, flag it (new approach)
            #    This assumes that any format variable not explicitly identified as safe is potentially external
            if any(pattern in var_lower for pattern in self.external_input_patterns):
                # Approach 1: Explicitly matches external input pattern
                if not any(safe_pattern in var_lower for safe_pattern in self.safe_internal_patterns):
                    external_inputs.add(var)
                    if os.environ.get('DEBUG') == "1":
                        print(f"  Found format variable: {var}")
            elif not any(safe_pattern in var_lower for safe_pattern in self.safe_internal_patterns):
                # Approach 2: Doesn't match any safe pattern - this is the key improvement
                # We consider any format variable not explicitly identified as safe to be potentially external
                external_inputs.add(var)
                if os.environ.get('DEBUG') == "1":
                    print(f"  Found format variable: {var}")
        
        if os.environ.get('DEBUG') == "1":
            print(f"  External inputs identified: {external_inputs}")
            
        return external_inputs
    
    def _extract_format_vars(self, content) -> List[str]:
        """Extract variables from string formatting patterns like {var} or {var_name}."""
        # Check if content is a string before applying regex
        if not isinstance(content, str):
            return []
            
        # Regular expression to capture variable names in format patterns
        pattern = r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}'
        matches = re.findall(pattern, content)
        return matches