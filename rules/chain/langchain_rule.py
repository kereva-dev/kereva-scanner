import ast
from typing import Any, Optional, Dict, List, Set
from rules.base_rule import BaseRule
from core.issue import Issue

class LangChainRule(BaseRule):
    """Rule to detect LangChain-specific vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            rule_id="chain-langchain",
            description="LangChain vulnerability detected",
            severity="medium"
        )
        
    def check(self, node_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check for LangChain-specific vulnerabilities."""
        context = context or {}
        
        # In a real implementation, this would check for things like:
        # - Unsafe RAG patterns in LangChain
        # - Unsanitized inputs in LangChain chains
        # - Issues with LangChain prompt templates
        
        # For demonstration purposes, we'll check for a simple pattern - direct
        # user input to graph.invoke() which is common in LangChain
        
        if isinstance(node_info, ast.Call):
            node = node_info
            if self._is_graph_invoke_with_user_input(node, context):
                return Issue(
                    rule_id=self.rule_id,
                    message="User input is passed directly to LangChain graph without validation",
                    location={
                        "line": getattr(node, "lineno", 0),
                        "file": context.get("file_name", "<unknown>")
                    },
                    severity=self.severity,
                    fix_suggestion="Validate user input before passing it to the LangChain graph to prevent prompt injection attacks"
                )
        
        return None
    
    def _is_graph_invoke_with_user_input(self, node: ast.Call, context: Dict[str, Any]) -> bool:
        """Check if this is a graph.invoke() call with user input."""
        # Check if this is a graph.invoke() call
        if isinstance(node.func, ast.Attribute) and node.func.attr == "invoke":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "graph":
                # Check if any arguments look like user input
                for arg in node.args:
                    if isinstance(arg, ast.Dict):
                        for i, key in enumerate(arg.keys):
                            if isinstance(key, ast.Str) and key.s in ["question", "query", "input"]:
                                value = arg.values[i]
                                # Check if value is a direct reference to user input
                                if isinstance(value, ast.Name) and value.id in ["user_input", "request", "query"]:
                                    return True
                                # Or if it's a function call that gets user input
                                elif isinstance(value, ast.Call):
                                    func_name = ""
                                    if isinstance(value.func, ast.Name):
                                        func_name = value.func.id
                                    elif isinstance(value.func, ast.Attribute):
                                        func_name = value.func.attr
                                    
                                    if func_name in ["input", "get_input", "prompt"]:
                                        return True
                
                # Check for keyword arguments as well
                for kw in node.keywords:
                    if kw.arg in ["question", "query", "input"]:
                        if isinstance(kw.value, ast.Name) and kw.value.id in ["user_input", "request", "query"]:
                            return True
        
        return False