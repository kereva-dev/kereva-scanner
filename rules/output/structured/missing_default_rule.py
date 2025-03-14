import ast
from typing import Optional, List, Dict, Any, Set
from rules.base_rule import BaseRule
from core.issue import Issue


class MissingDefaultRule(BaseRule):
    """Rule to check if structured output fields have default values to prevent hallucination.
    
    This rule ensures that fields in structured output models (e.g., Pydantic models)
    have default values or are marked as optional to prevent the model from hallucinating
    when data is missing.
    """
    
    def __init__(self):
        super().__init__(
            rule_id="output-structured-missing-default",
            description="Structured output fields should have default values to prevent hallucination",
            severity="medium"
        )
    
    def check(self, node: ast.AST, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if structured output fields have default values or are marked as optional."""
        context = context or {}
        
        # Only process ClassDef nodes
        if not isinstance(node, ast.ClassDef):
            return None
            
        # Check if this looks like a Pydantic model or other structured output definition
        if not self._is_structured_output_model(node):
            return None
            
        # Find fields without defaults
        fields_without_defaults = self._find_fields_without_defaults(node)
        
        # If there are fields without defaults, create an issue
        if fields_without_defaults:
            return self._create_issue(node, context, fields_without_defaults)
            
        return None
    
    def _is_structured_output_model(self, node: ast.ClassDef) -> bool:
        """Check if the class appears to be a structured output model."""
        # Look for inheritance from BaseModel or other model classes
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in ["BaseModel", "Schema", "Model"]:
                return True
            if isinstance(base, ast.Attribute):
                attr_chain = []
                current = base
                while isinstance(current, ast.Attribute):
                    attr_chain.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    attr_chain.append(current.id)
                if "BaseModel" in attr_chain or "Schema" in attr_chain or "Model" in attr_chain:
                    return True
                
        # Look for Config inner class - common in Pydantic models
        for item in node.body:
            if isinstance(item, ast.ClassDef) and item.name == "Config":
                return True
                
        # Look for typical field annotations or Field usage
        for item in node.body:
            if isinstance(item, ast.AnnAssign):
                if self._has_field_decorator(item):
                    return True
                    
        return False
    
    def _has_field_decorator(self, node: ast.AnnAssign) -> bool:
        """Check if an annotation assignment uses Field or similar decorators."""
        if node.value and isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id in ["Field", "field"]:
                return True
            if isinstance(node.value.func, ast.Attribute):
                attr_chain = []
                current = node.value.func
                while isinstance(current, ast.Attribute):
                    attr_chain.append(current.attr)
                    current = current.value
                if "Field" in attr_chain or "field" in attr_chain:
                    return True
        return False
    
    def _find_fields_without_defaults(self, node: ast.ClassDef) -> List[str]:
        """Find fields in a structured output model that don't have default values."""
        fields_without_defaults = []
        
        for item in node.body:
            # Check annotated assignments (typical for Pydantic models)
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                field_name = item.target.id
                
                # Skip dunder methods and properties
                if field_name.startswith('__') or field_name.startswith('_'):
                    continue
                    
                # Skip if it has a default value directly assigned
                if item.value is not None:
                    continue
                    
                # Check if it's using an Optional type or has None in a Union
                is_optional = self._is_optional_type(item.annotation)
                if is_optional:
                    continue
                    
                # If we got here, it's a non-optional field without a default
                fields_without_defaults.append(field_name)
                
        return fields_without_defaults
    
    def _is_optional_type(self, annotation) -> bool:
        """Check if a type annotation is Optional or Union with None."""
        # Check for Optional[...]
        if isinstance(annotation, ast.Subscript):
            if isinstance(annotation.value, ast.Name) and annotation.value.id == "Optional":
                return True
            
            # Check for Union[..., None] or Union[None, ...]
            if isinstance(annotation.value, ast.Name) and annotation.value.id == "Union":
                # Try to extract the arguments
                if hasattr(annotation.slice, "value") and isinstance(annotation.slice.value, ast.Tuple):
                    for elt in annotation.slice.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value is None:
                            return True
                        if isinstance(elt, ast.Name) and elt.id == "None":
                            return True

        return False
    
    def _create_issue(self, node, context, fields_without_defaults):
        """Create an issue for this rule violation."""
        fields_str = ", ".join(fields_without_defaults)
        message = f"Fields in structured output models should have default values or be Optional (fields without defaults: {fields_str})"
            
        return Issue(
            rule_id=self.rule_id,
            message=message,
            location={
                "line": getattr(node, 'lineno', 0),
                "column": getattr(node, 'col_offset', 0),
                "file": context.get("file_name", "<unknown>")
            },
            severity=self.severity,
            fix_suggestion="Add default values (e.g., Field(default='')) or make fields Optional[type] to prevent hallucination when data is missing"
        )