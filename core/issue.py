from typing import Dict, Any, List, Optional

class Issue:
    """Representation of an issue found during scanning."""
    
    def __init__(
        self,
        rule_id: str,
        message: str,
        location: Dict[str, Any],
        severity: str = "medium",
        fix_suggestion: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None
    ):
        self.rule_id = rule_id
        self.message = message
        self.location = location
        self.severity = severity
        self.fix_suggestion = fix_suggestion
        self.context = context or {}
        self.tags = tags or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the issue to a dictionary."""
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "location": self.location,
            "severity": self.severity,
            "fix_suggestion": self.fix_suggestion,
            "context": self.context,
            "tags": self.tags
        }
