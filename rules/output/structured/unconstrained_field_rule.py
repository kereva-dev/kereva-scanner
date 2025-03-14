import ast
from typing import Any, Optional, Dict, List
from core.issue import Issue
from rules.base_rule import BaseRule


class UnconstrainedFieldRule(BaseRule):
    """Rule to check for Pydantic model fields without constraints."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-structured-unconstrained-field",
            description="Pydantic model fields used for LLM output should have constraints",
            severity="medium"
        )
        
        # Types that should have constraints in LLM output schemas
        self.should_be_constrained = {
            'str': ['min_length', 'max_length', 'pattern', 'regex', 
                   'enum', 'literal', 'constr', 'choices'],
            'int': ['ge', 'gt', 'le', 'lt', 'multiple_of', 
                   'enum', 'literal', 'conint'],
            'float': ['ge', 'gt', 'le', 'lt', 'multiple_of', 
                     'enum', 'literal', 'confloat'],
            'list': ['min_items', 'max_items', 'unique_items', 'items', 'conlist'],
            'dict': ['min_keys', 'max_keys', 'schema', 'condict']
        }
        
        # Types that are naturally constrained
        self.inherently_constrained = [
            'Enum', 'Literal', 'date', 'datetime', 'time', 'UUID', 'Email',
            'HttpUrl', 'IPvAnyAddress', 'Json', 'PaymentCardNumber', 'StrictStr', 
            'StrictInt', 'StrictFloat', 'StrictBool', 'FilePath', 'DirectoryPath'
        ]
        
        # Pydantic validator decorators
        self.validator_decorators = [
            'validator', 'root_validator', 'field_validator'
        ]
    
    def check(self, node: Dict[str, Any], context: Optional[dict] = None) -> Optional[Issue]:
        """Check if a Pydantic model field lacks constraints."""
        context = context or {}
        
        # Only process if this is a Pydantic field in an LLM output model
        if not (node.get("is_pydantic_field", False) and 
                node.get("is_llm_output_model", False)):
            return None
        
        field_name = node.get("field_name", "unknown")
        model_name = node.get("model_name", "unknown")
        base_type = node.get("base_type", "unknown")
        
        # Skip fields that don't need constraints (bool, None, object...)
        if base_type not in self.should_be_constrained:
            return None
            
        # Skip if using a naturally constrained type
        annotation = node.get("annotation", "")
        if any(constrained_type in annotation for constrained_type in self.inherently_constrained):
            return None
            
        # Check if there are constraints in Field(...)
        field_kwargs = node.get("field_kwargs", {})
        needed_constraints = self.should_be_constrained.get(base_type, [])
        
        has_constraints = any(constraint in field_kwargs for constraint in needed_constraints)
        
        # If no constraints in Field, check if there's a validator for this field
        if not has_constraints:
            validators = node.get("validators", [])
            if not validators:
                location = node.get("location", {})
                suggested_constraints = self._get_suggested_constraints(base_type)
                
                return Issue(
                    rule_id=self.rule_id,
                    message=f"Field '{field_name}' in model '{model_name}' lacks constraints for type '{base_type}'",
                    location=location,
                    severity=self.severity,
                    fix_suggestion=f"Add constraints to the field using Field({suggested_constraints})",
                    context={
                        "field_name": field_name,
                        "model_name": model_name,
                        "field_type": base_type,
                        "suggested_constraints": suggested_constraints
                    }
                )
                
        return None
    
    def _get_suggested_constraints(self, base_type: str) -> str:
        """Get suggested constraints for a given type."""
        if base_type == 'str':
            return "min_length=1, max_length=100"
        elif base_type == 'int':
            return "ge=0, le=1000"
        elif base_type == 'float':
            return "ge=0.0, le=1.0"
        elif base_type == 'list':
            return "min_items=0, max_items=100"
        elif base_type == 'dict':
            return "min_keys=1, max_keys=20"
        else:
            return "..."