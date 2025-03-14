import ast
import os
from typing import List, Dict, Any, Optional, Set, Tuple
from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from rules.output.structured.missing_description_rule import MissingDescriptionRule
from rules.output.structured.unconstrained_field_rule import UnconstrainedFieldRule
from rules.output.structured.missing_default_rule import MissingDefaultRule


class StructuredScanner(BaseScanner):
    """Scanner for structured output models used for LLM response parsing."""
    
    def __init__(self):
        rules = [
            MissingDescriptionRule(),
            UnconstrainedFieldRule(),
            MissingDefaultRule()
        ]
        super().__init__(rules)
        
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan for structured output model issues."""
        context = context or {}
        visitor = StructuredOutputVisitor(self.rules, context, self.rule_applier)
        visitor.visit(ast_node)
        self.issues = visitor.issues
        return self.issues


class StructuredOutputVisitor(BaseVisitor):
    """AST visitor for finding structured output model definitions."""
    
    def __init__(self, rules, context, rule_applier):
        super().__init__(context)
        self.rules = rules
        self.rule_applier = rule_applier
        self.issues = []
        self.pydantic_imports = set()
        self.llm_related_models = set()
        self.current_module = None
        
    def visit_Module(self, node):
        """Keep track of the current module and process after all classes are visited."""
        self.current_module = node
        self.llm_related_models = set()  # Reset for this module
        
        # First pass - gather all classes
        self.generic_visit(node)
        
        # Second pass - identify LLM output models
        # We do this after all classes are visited to handle nested relationships
        pydantic_models = {}
        for class_name, class_node in self.classes.items():
            if self._is_pydantic_model(class_node):
                pydantic_models[class_name] = class_node
        
        # Look for direct references to OpenAI function tools
        direct_function_tool_usage = False
        direct_tool_model = None
        for top_level_node in node.body:
            if isinstance(top_level_node, ast.Assign) and top_level_node.value:
                for sub_node in ast.walk(top_level_node.value):
                    if (isinstance(sub_node, ast.Call) and 
                        isinstance(sub_node.func, ast.Attribute) and
                        sub_node.func.attr in ['parse']):
                        
                        # Look for the tools parameter which indicates OpenAI function calling
                        for kw in sub_node.keywords:
                            if kw.arg == 'tools' and isinstance(kw.value, ast.List):
                                for tool_item in kw.value.elts:
                                    if (isinstance(tool_item, ast.Call) and
                                        isinstance(tool_item.func, ast.Attribute) and
                                        tool_item.func.attr == 'pydantic_function_tool' and
                                        len(tool_item.args) > 0 and
                                        isinstance(tool_item.args[0], ast.Name)):
                                        
                                        # Found direct usage: openai.pydantic_function_tool(ModelClass)
                                        direct_function_tool_usage = True
                                        direct_tool_model = tool_item.args[0].id
                                        break
                            if direct_function_tool_usage:
                                break
                    if direct_function_tool_usage:
                        break
                if direct_function_tool_usage:
                    break
        
        # If we found direct function tool usage, prioritize this model and all its nested types
        direct_llm_models = set()
        if direct_function_tool_usage and direct_tool_model and direct_tool_model in pydantic_models:
            direct_llm_models.add(direct_tool_model)
            self.llm_related_models.add(direct_tool_model)
            
            # Debug output
            if os.environ.get('DEBUG') == "1":
                print(f"Found direct OpenAI function tool usage with model: {direct_tool_model}")
        
        # Also check each model for function tool usage
        for class_name, class_node in pydantic_models.items():
            # Try to detect if this model is directly used in function calling
            if self._model_used_as_llm_function_tool(class_node):
                direct_llm_models.add(class_name)
                self.llm_related_models.add(class_name)
        
        # Then identify models referenced by those models (recursively)
        processed = set()
        while direct_llm_models:
            model_name = direct_llm_models.pop()
            if model_name in processed:
                continue
                
            processed.add(model_name)
            class_node = pydantic_models.get(model_name)
            if not class_node:
                continue
                
            # Find all referenced types
            for field_node in class_node.body:
                if isinstance(field_node, ast.AnnAssign) and field_node.annotation:
                    referenced_types = self._extract_field_types(field_node.annotation)
                    for ref_type in referenced_types:
                        if ref_type in pydantic_models and ref_type not in processed:
                            # This is another Pydantic model referenced by a model used in function calling
                            direct_llm_models.add(ref_type)
                            self.llm_related_models.add(ref_type)
        
        # Debug output
        if os.environ.get('DEBUG') == "1":
            print(f"LLM-related models: {self.llm_related_models}")
        
        # Now process all LLM-related models
        for class_name in self.llm_related_models:
            class_node = self.classes.get(class_name)
            if not class_node:
                continue
                
            # Process class like before
            # Check class-level docstring for completeness
            class_docstring = ast.get_docstring(class_node)
            
            # Process each field in the model
            field_infos = []
            for field_node in class_node.body:
                if isinstance(field_node, ast.AnnAssign) and isinstance(field_node.target, ast.Name):
                    field_info = self._extract_field_info(field_node, class_node.name, True)
                    field_infos.append(field_info)
            
            # Apply field-level rules to all fields
            field_level_issues = self.rule_applier.apply_rule_batch(
                field_infos,
                self.context,
                filter_func=lambda rule: rule.rule_id != "output-structured-missing-default"
            )
            self.issues.extend(field_level_issues)
            
            # Apply class-level rules to the entire class
            class_level_issues = self.rule_applier.apply_rules(
                class_node,
                self.context,
                filter_func=lambda rule: rule.rule_id == "output-structured-missing-default"
            )
            self.issues.extend(class_level_issues)
            
    def _extract_field_types(self, annotation) -> List[str]:
        """Extract type names from a field annotation."""
        type_names = []
        
        # Direct reference to a class
        if isinstance(annotation, ast.Name):
            type_names.append(annotation.id)
            
        # Handle Union[Type1, Type2], List[Type], etc.
        elif isinstance(annotation, ast.Subscript):
            # Get the base type (List, Union, etc.)
            if isinstance(annotation.value, ast.Name):
                base_type = annotation.value.id
                
                # List[T], list[T] - extract the inner type
                if base_type.lower() in ['list', 'set', 'sequence', 'tuple']:
                    # Python 3.8 and earlier
                    if hasattr(annotation.slice, 'value'):
                        if isinstance(annotation.slice.value, ast.Name):
                            type_names.append(annotation.slice.value.id)
                        # For complex types like list[Union[...]]
                        elif isinstance(annotation.slice.value, ast.Subscript):
                            type_names.extend(self._extract_field_types(annotation.slice.value))
                    # Python 3.9+
                    else:
                        for sub_node in ast.walk(annotation.slice):
                            if isinstance(sub_node, ast.Name):
                                type_names.append(sub_node.id)
                
                # Union[T1, T2, ...], Optional[T] - extract all types
                elif base_type in ['Union', 'Optional']:
                    # Python 3.8 and earlier
                    if hasattr(annotation.slice, 'value'):
                        if isinstance(annotation.slice.value, ast.Tuple):
                            for elt in annotation.slice.value.elts:
                                if isinstance(elt, ast.Name):
                                    type_names.append(elt.id)
                                elif isinstance(elt, ast.Subscript):
                                    type_names.extend(self._extract_field_types(elt))
                        elif isinstance(annotation.slice.value, ast.Name):
                            type_names.append(annotation.slice.value.id)
                        elif isinstance(annotation.slice.value, ast.Subscript):
                            type_names.extend(self._extract_field_types(annotation.slice.value))
                    # Python 3.9+
                    else:
                        for sub_node in ast.walk(annotation.slice):
                            if isinstance(sub_node, ast.Name) and sub_node.id != 'None':
                                type_names.append(sub_node.id)
                            elif isinstance(sub_node, ast.Subscript):
                                type_names.extend(self._extract_field_types(sub_node))
        
        # Debug output
        if os.environ.get('DEBUG') == "1" and type_names:
            print(f"Extracted field types: {type_names}")
            
        return type_names
        
    def visit_Import(self, node):
        """Track imports to detect Pydantic usage."""
        # Let BaseVisitor handle standard import tracking
        super().visit_Import(node)
        
        # Add our specific tracking for Pydantic
        for name in node.names:
            if name.name == 'pydantic':
                self.pydantic_imports.add(name.name)
        
    def visit_ImportFrom(self, node):
        """Track imports to detect Pydantic usage."""
        # Let BaseVisitor handle standard import tracking
        super().visit_ImportFrom(node)
        
        # Add our specific tracking for Pydantic
        if node.module == 'pydantic':
            for name in node.names:
                self.pydantic_imports.add(f"pydantic.{name.name}")
        
    def visit_ClassDef(self, node):
        """Visit class definitions to find Pydantic models."""
        # Let BaseVisitor handle tracking class definitions
        # which will update self.current_class and self.classes
        super().visit_ClassDef(node)
        
        # Save the current class name to restore after our specific processing
        current_class_name = self.current_class
        
        # Check if this is a Pydantic model
        is_pydantic_model = self._is_pydantic_model(node)
        is_llm_output_model = False
        
        # Debug output
        if os.environ.get('DEBUG') == "1":
            print(f"Checking class: {node.name}, is_pydantic_model: {is_pydantic_model}")
        
        # First pass - just identify pydantic models and save them, but don't analyze yet
        if is_pydantic_model:
            self.classes[node.name] = node
        
        # Wait until we've processed all classes to determine LLM output models
        # This is done in the generic_visit method after all class definitions are processed
        
    def _extract_field_info(self, node, model_name, is_llm_output_model) -> Dict[str, Any]:
        """Extract information about a Pydantic model field."""
        field_info = {
            "is_pydantic_field": True,
            "is_llm_output_model": is_llm_output_model,
            "field_name": node.target.id if isinstance(node.target, ast.Name) else "unknown",
            "model_name": model_name,
            "location": {
                "file": self.context.get("file_name", "<unknown>"),
                "line": node.lineno,
                "column": node.col_offset,
            },
            "field_kwargs": {},
            "field_docstring": None,
            "validators": [],
        }
        
        # Extract type annotation and base type (for constraint checking)
        if node.annotation:
            annotation_str = self._get_annotation_as_string(node.annotation)
            field_info["annotation"] = annotation_str
            
            # Extract the base type (str, int, float, etc.)
            base_type = self._get_base_type(node.annotation, annotation_str)
            field_info["base_type"] = base_type
        
        # Extract Field parameters if present
        if isinstance(node.value, ast.Call) and self._is_pydantic_field_call(node.value):
            field_kwargs = self._extract_field_kwargs(node.value)
            field_info["field_kwargs"] = field_kwargs
        
        # Check for inline comment or following string literal as docstring
        field_info["field_docstring"] = self._get_field_docstring(node)
        
        # Find validators for this field
        field_info["validators"] = self._find_validators_for_field(field_info["field_name"])
        
        return field_info
        
    def _get_base_type(self, annotation_node, annotation_str) -> str:
        """Extract the base type from a type annotation."""
        if isinstance(annotation_node, ast.Name):
            return annotation_node.id.lower()
        elif isinstance(annotation_node, ast.Subscript):
            if isinstance(annotation_node.value, ast.Name):
                base = annotation_node.value.id.lower()
                # Handle common container types
                if base in ['list', 'set', 'tuple', 'dict', 'optional']:
                    return base
                # Handle special case for Literal
                if base == 'literal':
                    return 'literal'
            # Check the string representation for common types
            if 'str' in annotation_str.lower():
                return 'str'
            elif 'int' in annotation_str.lower():
                return 'int'
            elif 'float' in annotation_str.lower():
                return 'float'
            elif 'bool' in annotation_str.lower():
                return 'bool'
        return "unknown"
        
    def _find_validators_for_field(self, field_name) -> List[Dict[str, Any]]:
        """Find validator methods that apply to this field."""
        validators = []
        
        # Search the class body for validator decorators
        if self.current_class and self.current_module:
            for node in ast.iter_child_nodes(self.current_module):
                if (isinstance(node, ast.ClassDef) and 
                    node.name == self.current_class):
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            # Check for validator decorators
                            for decorator in item.decorator_list:
                                if self._is_validator_decorator(decorator, field_name):
                                    validators.append({
                                        "name": item.name,
                                        "line": item.lineno
                                    })
        
        return validators
        
    def _is_validator_decorator(self, decorator_node, field_name) -> bool:
        """Check if a decorator is a validator for the specified field."""
        # Look for @validator('field_name')
        if isinstance(decorator_node, ast.Call):
            if isinstance(decorator_node.func, ast.Name):
                if decorator_node.func.id in ['validator', 'field_validator']:
                    # Check for field name in args
                    for arg in decorator_node.args:
                        if (isinstance(arg, ast.Str) or 
                            (hasattr(ast, 'Constant') and isinstance(arg, ast.Constant))):
                            arg_value = arg.s if hasattr(arg, 's') else arg.value
                            if arg_value == field_name or arg_value == '*':
                                return True
        return False
    
    def _get_annotation_as_string(self, annotation) -> str:
        """Convert a type annotation AST node to a string representation."""
        if isinstance(annotation, ast.Name):
            return annotation.id
        elif isinstance(annotation, ast.Subscript):
            # Handle generic types like List[str], Optional[int], etc.
            if isinstance(annotation.value, ast.Name):
                base = annotation.value.id
                if hasattr(annotation.slice, 'value'):  # Python 3.8 and below
                    if isinstance(annotation.slice.value, ast.Name):
                        arg = annotation.slice.value.id
                    else:
                        arg = "..."
                else:  # Python 3.9+
                    arg = "..."
                return f"{base}[{arg}]"
        return "unknown"
    
    def _extract_field_kwargs(self, field_call) -> Dict[str, Any]:
        """Extract keyword arguments from a Field(...) call."""
        kwargs = {}
        for kw in field_call.keywords:
            if kw.arg == 'description':
                if isinstance(kw.value, ast.Str) or (
                    hasattr(ast, 'Constant') and 
                    isinstance(kw.value, ast.Constant) and 
                    isinstance(kw.value.value, str)
                ):
                    kwargs['description'] = kw.value.s if hasattr(kw.value, 's') else kw.value.value
        return kwargs
    
    def _get_field_docstring(self, node) -> Optional[str]:
        """Try to find a docstring comment for a field."""
        # Check for a string literal that follows the field assignment
        if getattr(node, 'end_lineno', 0) > 0:
            for child in ast.iter_child_nodes(self.current_module):
                if (isinstance(child, ast.Expr) and 
                    isinstance(child.value, (ast.Str, ast.Constant)) and
                    getattr(child, 'lineno', 0) == node.end_lineno + 1):
                    return child.value.s if hasattr(child.value, 's') else child.value.value
        return None
    
    def _is_pydantic_model(self, node) -> bool:
        """Determine if a class is a Pydantic model."""
        # Check for BaseModel inheritance
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == 'BaseModel':
                return True
            elif isinstance(base, ast.Attribute) and base.attr == 'BaseModel':
                return True
                
        # If not directly inheriting, check if it's used in a way that strongly suggests it's a Pydantic model
        # 1. Check if it's used with openai.pydantic_function_tool()
        # This is important for OpenAI function/tool models that might inherit from a custom BaseModel subclass
        class_name = node.name
        for module_node in ast.iter_child_nodes(self.current_module):
            for n in ast.walk(module_node):
                if (isinstance(n, ast.Call) and 
                    isinstance(n.func, ast.Attribute) and
                    n.func.attr in ['pydantic_function_tool', 'function_tool'] and
                    len(n.args) > 0 and
                    isinstance(n.args[0], ast.Name) and 
                    n.args[0].id == class_name):
                    return True
                
                # Also check if it's used in tools/functions arguments
                if isinstance(n, ast.Call):
                    for keyword in n.keywords:
                        if keyword.arg in ['tools', 'functions', 'tool_choice']:
                            for sub_node in ast.walk(keyword.value):
                                if isinstance(sub_node, ast.Name) and sub_node.id == class_name:
                                    return True
        
        return False
    
    def _is_pydantic_field_call(self, node) -> bool:
        """Check if a node is a call to pydantic.Field."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'Field':
                return True
            elif (isinstance(node.func, ast.Attribute) and 
                  node.func.attr == 'Field' and 
                  isinstance(node.func.value, ast.Name) and 
                  node.func.value.id == 'pydantic'):
                return True
        return False
        
    def _is_llm_output_model(self, node) -> bool:
        """
        Determine if a Pydantic model is likely used for LLM output structuring.
        Uses a combination of strong and weak signals to make a more accurate determination.
        """
        strong_evidence = False
        weak_evidence_count = 0
        
        # Strong evidence: Explicit mention of LLM output parsing in docstring
        docstring = ast.get_docstring(node)
        if docstring:
            # Strong evidence keywords are more specific to LLM output parsing
            strong_keywords = ['llm output', 'gpt output', 'claude output', 'model response',
                               'parse llm', 'parse gpt', 'parse claude', 'structured output',
                               'llm response schema', 'output schema for llm', 'openai response']
            
            if any(keyword in docstring.lower() for keyword in strong_keywords):
                strong_evidence = True
            
            # Weak evidence keywords are more general
            weak_keywords = ['ai', 'output', 'response', 'schema', 'parse', 'parsing']
            if any(keyword in docstring.lower() for keyword in weak_keywords):
                weak_evidence_count += 1
        
        # Check if model is used in OpenAI function tools or other direct SDK integrations
        if self._model_used_as_llm_function_tool(node):
            strong_evidence = True
            
        # Check if model is part of a function call hierarchy (nested in another model used in function calling)
        if self._is_used_in_function_hierarchy(node):
            strong_evidence = True
        
        # Check if model is used to handle LLM API responses
        model_processes_llm_output = self._model_processes_llm_responses(node)
        if model_processes_llm_output:
            strong_evidence = True
        
        # Strong evidence from class name
        strong_llm_class_names = ['llmresponse', 'gptresponse', 'clauderesponse', 
                                  'llmresult', 'llmoutput', 'completionresult',
                                  'chatresponse', 'openairesponse', 'aioutputschema']
        
        if any(term in node.name.lower() for term in strong_llm_class_names):
            strong_evidence = True
            
        # Special names for OpenAI function calling
        function_tool_names = ['query', 'condition', 'parameter', 'action', 'function',
                              'argument', 'option', 'command', 'tool', 'requestbody']
        if any(term in node.name.lower() for term in function_tool_names):
            weak_evidence_count += 1
            
        # Generic response/result names (weak evidence)
        weak_llm_class_names = ['response', 'output', 'result', 'schema']
        if any(term in node.name.lower() for term in weak_llm_class_names):
            weak_evidence_count += 1
        
        # Look through the module for functions using LLM APIs that also use this model
        model_used_with_llm_api = self._model_used_with_llm_api(node)
        if model_used_with_llm_api:
            strong_evidence = True
        
        # Check field types for JSON schema validation fields characteristic of LLM output models
        if self._has_llm_output_model_fields(node):
            weak_evidence_count += 1
        
        # Strong evidence alone is enough to determine this is an LLM output model
        if strong_evidence:
            return True
            
        # Multiple pieces of weak evidence are required without strong evidence
        return weak_evidence_count >= 2
    
    def _model_used_as_llm_function_tool(self, model_node) -> bool:
        """Check if the model is used as an OpenAI function/tool specification."""
        class_name = model_node.name
        
        for module_node in ast.iter_child_nodes(self.current_module):
            for node in ast.walk(module_node):
                # Pattern: openai.pydantic_function_tool(ModelClass)
                if (isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Attribute) and
                    node.func.attr in ['pydantic_function_tool', 'function_tool', 'register_tool'] and
                    len(node.args) > 0):
                    
                    # Check if the first argument is our model
                    if isinstance(node.args[0], ast.Name) and node.args[0].id == class_name:
                        return True
                
                # Pattern: tools=[{"type": "function", "function": {"model": ModelClass}}]
                # Pattern: schema="function" with model reference
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg in ['tools', 'functions', 'schemas', 'schema']:
                            for sub_node in ast.walk(keyword.value):
                                if isinstance(sub_node, ast.Name) and sub_node.id == class_name:
                                    return True
                
                # Pattern: client.chat.completions.parse(...) with model reference
                if (isinstance(node, ast.Call) and 
                    isinstance(node.func, ast.Attribute) and
                    node.func.attr in ['parse', 'create_with_structured_response']):
                    
                    # Scan for model mentions in keywords or nested arguments
                    found_in_args = False
                    for arg in ast.walk(node):
                        if isinstance(arg, ast.Name) and arg.id == class_name:
                            found_in_args = True
                            break
                    if found_in_args:
                        return True
        
        # Check if any field or class in the type hierarchy is used in a function tool
        # This handles nested models where one model references another in a chain
        if hasattr(model_node, 'body'):
            for field_node in model_node.body:
                if isinstance(field_node, ast.AnnAssign) and field_node.annotation:
                    # Check if the field type is another Pydantic model that's used in function calling
                    field_type = None
                    if isinstance(field_node.annotation, ast.Name):
                        field_type = field_node.annotation.id
                    elif isinstance(field_node.annotation, ast.Subscript) and isinstance(field_node.annotation.value, ast.Name):
                        # Handle list[Type] or Union[Type1, Type2]
                        if field_node.annotation.value.id in ['list', 'List']:
                            # Extract the type inside the list
                            if hasattr(field_node.annotation.slice, 'value') and isinstance(field_node.annotation.slice.value, ast.Name):
                                field_type = field_node.annotation.slice.value.id
                    
                    # If we found a field type that might be another model, check if it's used in function calling
                    if field_type and field_type in self.llm_related_models:
                        return True
        
        return False
    
    def _is_used_in_function_hierarchy(self, model_node) -> bool:
        """Check if this model is part of a hierarchy used in function calling."""
        class_name = model_node.name
        
        # Check if this model is referenced as a field type in any other models that are used in function calling
        for module_node in ast.iter_child_nodes(self.current_module):
            if isinstance(module_node, ast.ClassDef) and self._is_pydantic_model(module_node):
                # Skip checking the model against itself
                if module_node.name == class_name:
                    continue
                    
                # If this model contains a field of type class_name and is used in function calling
                for field_node in module_node.body:
                    if isinstance(field_node, ast.AnnAssign) and field_node.annotation:
                        # Check direct field type
                        if isinstance(field_node.annotation, ast.Name) and field_node.annotation.id == class_name:
                            # If the parent model is used in function calling, this model is part of the hierarchy
                            if self._model_used_as_llm_function_tool(module_node):
                                return True
                                
                        # Check nested types like list[Type] or Union[Type1, Type2]
                        elif isinstance(field_node.annotation, ast.Subscript):
                            for subnode in ast.walk(field_node.annotation):
                                if isinstance(subnode, ast.Name) and subnode.id == class_name:
                                    if self._model_used_as_llm_function_tool(module_node):
                                        return True
        
        return False
    
    def _model_processes_llm_responses(self, model_node) -> bool:
        """Check if model is used in a function that processes LLM API responses."""
        class_name = model_node.name
        
        for module_node in ast.iter_child_nodes(self.current_module):
            if isinstance(module_node, ast.FunctionDef):
                # Look for functions that both reference the model and contain LLM API calls
                contains_llm_api = False
                
                # Search function body for LLM API calls
                for node in ast.walk(module_node):
                    if isinstance(node, ast.Call):
                        # Check if the call matches LLM API patterns from config
                        from core.config import LLM_API_PATTERNS
                        from core.ast_utils import is_call_matching
                        
                        if is_call_matching(node, LLM_API_PATTERNS):
                            contains_llm_api = True
                            break
                
                if contains_llm_api and self._function_references_class(module_node, class_name):
                    # Look for assignment patterns that suggest parsing LLM outputs
                    for node in ast.walk(module_node):
                        # Pattern: model_instance = ModelClass.parse_raw(response.text)
                        # Pattern: model_instance = ModelClass.model_validate(response.json())
                        if (isinstance(node, ast.Assign) and
                            isinstance(node.value, ast.Call) and
                            isinstance(node.value.func, ast.Attribute) and
                            node.value.func.attr in ['parse_raw', 'model_validate', 'parse_obj',
                                                    'from_response', 'from_json']):
                            if (isinstance(node.value.func.value, ast.Name) and 
                                node.value.func.value.id == class_name):
                                return True
                        
                        # Pattern: ModelClass(**response.json())
                        if (isinstance(node, ast.Call) and
                            isinstance(node.func, ast.Name) and
                            node.func.id == class_name and
                            any(isinstance(kw.value, ast.Call) for kw in node.keywords)):
                            return True
        
        return False
    
    def _model_used_with_llm_api(self, model_node) -> bool:
        """Check if the model is used in conjunction with LLM API calls."""
        class_name = model_node.name
        
        for module_node in ast.iter_child_nodes(self.current_module):
            if isinstance(module_node, ast.FunctionDef):
                # Check for functions with LLM-specific names and docstrings
                llm_func_names = ['get_llm_response', 'call_llm', 'ask_llm', 'query_gpt',
                                 'generate_text', 'complete_prompt', 'chatgpt_request']
                                 
                if any(term in module_node.name.lower() for term in llm_func_names):
                    if self._function_references_class(module_node, class_name):
                        return True
                
                # Check for function annotations that suggest LLM APIs
                returns_annotation = module_node.returns
                if returns_annotation and isinstance(returns_annotation, ast.Name):
                    if returns_annotation.id == class_name:
                        # Function returns our model - now check if it calls LLM APIs
                        for node in ast.walk(module_node):
                            if isinstance(node, ast.Call):
                                from core.config import LLM_API_PATTERNS
                                from core.ast_utils import is_call_matching
                                
                                if is_call_matching(node, LLM_API_PATTERNS):
                                    return True
        
        return False
    
    def _has_llm_output_model_fields(self, node) -> bool:
        """Check if the model has fields typical of LLM output schemas."""
        # Look for fields commonly found in LLM output models
        llm_output_field_patterns = [
            'completion', 'generated_text', 'response', 'answer', 'content',
            'message', 'reasoning', 'rationale', 'explanation', 'thoughts',
            'confidence', 'certainty', 'choices', 'options'
        ]
        
        # Count fields matching LLM output patterns
        matching_fields = 0
        
        for item in node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                field_name = item.target.id.lower()
                if any(pattern in field_name for pattern in llm_output_field_patterns):
                    matching_fields += 1
                    
                # Check for specialized fields: scores, probabilities, token counts
                if any(term in field_name for term in ['score', 'probability', 'token', 'confidence']):
                    matching_fields += 1
        
        # If multiple fields match LLM output patterns, it's likely an LLM output model
        return matching_fields >= 2
    
    def _function_references_class(self, func_node, class_name) -> bool:
        """Check if a function uses or returns a specific class."""
        class_finder = ClassReferenceVisitor(class_name)
        class_finder.visit(func_node)
        return class_finder.references_class


class ClassReferenceVisitor(ast.NodeVisitor):
    """Helper visitor to check if a function references a specific class."""
    
    def __init__(self, class_name):
        self.class_name = class_name
        self.references_class = False
        
    def visit_Name(self, node):
        """Check for class name references."""
        if node.id == self.class_name:
            self.references_class = True
        self.generic_visit(node)
        
    def visit_Return(self, node):
        """Check if a function returns the class."""
        if node.value and isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id == self.class_name:
                self.references_class = True
        self.generic_visit(node)