from abc import ABC, abstractmethod
from typing import Any, List, Optional
from core.issue import Issue

class BaseRule(ABC):
    """Abstract base class for all rules."""
    
    def __init__(self, rule_id: str, description: str, severity: str = "medium", tags: Optional[List[str]] = None):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.tags = tags or []
    
    @abstractmethod
    def check(self, node: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if the rule is violated and return an Issue if it is."""
        pass
