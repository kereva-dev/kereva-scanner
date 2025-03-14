import ast
from typing import Any, Optional, Dict, List
from core.issue import Issue
from rules.base_rule import BaseRule


class MissingDescriptionRule(BaseRule):
    """Rule to check for Pydantic model fields without descriptions."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-structured-missing-description",
            description="Pydantic model fields used for LLM output should have descriptions",
            severity="low"
        )
    
    def check(self, node: Dict[str, Any], context: Optional[dict] = None) -> Optional[Issue]:
        """Check if a Pydantic model field lacks a description."""
        context = context or {}
        
        # Only process if this is a Pydantic model field
        if not node.get("is_pydantic_field", False):
            return None
            
        # Check if the field has a description
        has_description = False
        
        # Check for Field(..., description="...")
        if node.get("field_kwargs", {}).get("description"):
            has_description = True
            
        # Check for docstring after the field
        elif node.get("field_docstring"):
            has_description = True
            
        # If no description found and it's a field for LLM output, report issue
        if not has_description and node.get("is_llm_output_model", False):
            location = node.get("location", {})
            field_name = node.get("field_name", "unknown")
            model_name = node.get("model_name", "unknown")
            
            return Issue(
                rule_id=self.rule_id,
                message=f"Field '{field_name}' in model '{model_name}' lacks a description",
                location=location,
                severity=self.severity,
                fix_suggestion=f"Add a description to the field using Field(..., description='What this field represents') or add a docstring comment",
                context={"field_name": field_name, "model_name": model_name}
            )
            
        return None