import ast
from typing import Any, Optional, Dict, List
from rules.base_rule import BaseRule
from core.issue import Issue

class UnsafeInputRule(BaseRule):
    """Rule to detect untrusted input flowing through LLM chains without sanitization."""
    
    def __init__(self):
        super().__init__(
            rule_id="chain-unsafe-input",
            description="Untrusted input flows directly through LLM chain without sanitization",
            severity="high",
            tags = ["prompt injection", "OWASP LLM01", "OWASP LLM02", "OWASP LLM05"]
        )
        # Default untrusted input parameter names (can be customized through context)
        self.default_untrusted_params = [
            "user_input", "query", "prompt", "user_message", "request", "input"
        ]
        
    def check(self, node_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if untrusted input flows through LLM chain without sanitization."""
        # This rule handles two types of inputs:
        # 1. AST nodes (from direct scanner processing)
        # 2. Prompt data dictionaries (from PromptScanner)
        
        if isinstance(node_info, ast.AST):
            # Handle AST node input (original behavior)
            node = node_info
            context = context or {}
            # Get untrusted parameters (use default or custom from context)
            untrusted_params = context.get("untrusted_params", self.default_untrusted_params)
            
            # Find all variable assignments
            assignments = self._collect_assignments(node)
            
            # Find all LLM API calls
            llm_calls = self._collect_llm_calls(node)
            
            # Find paths from untrusted input to LLM calls
            for param in untrusted_params:
                for llm_call in llm_calls:
                    if self._has_unsanitized_path(param, llm_call, assignments):
                        return Issue(
                            rule_id=self.rule_id,
                            message=f"Untrusted input '{param}' flows directly to LLM call without sanitization",
                            location=self._get_location(llm_call),
                            severity=self.severity,
                            fix_suggestion="Implement input validation or use a allow-list approach for user inputs",
                            context={"param": param, "llm_call": ast.dump(llm_call)}
                        )
        elif isinstance(node_info, dict) and 'content' in node_info:
            # Handle prompt data dictionary from PromptScanner
            # (This rule doesn't need to do anything with this type of input)
            return None
                    
        return None
    
    def _collect_assignments(self, node: ast.AST) -> Dict[str, List[ast.AST]]:
        """Collect all variable assignments in the AST."""
        assignments = {}
        
        class AssignmentVisitor(ast.NodeVisitor):
            def visit_Assign(self, assign_node):
                for target in assign_node.targets:
                    if isinstance(target, ast.Name):
                        if target.id not in assignments:
                            assignments[target.id] = []
                        assignments[target.id].append(assign_node)
                self.generic_visit(assign_node)
                
        AssignmentVisitor().visit(node)
        return assignments
    
    def _collect_llm_calls(self, node: ast.AST) -> List[ast.Call]:
        """Collect all LLM API calls in the AST."""
        llm_calls = []
        
        class LLMCallVisitor(ast.NodeVisitor):
            def visit_Call(self, call_node):
                if self._is_llm_api_call(call_node):
                    llm_calls.append(call_node)
                self.generic_visit(call_node)
                
            def _is_llm_api_call(self, node):
                """Check if this node is an LLM API call."""
                # Method chains (e.g., client.create, openai.Completion.create)
                if isinstance(node.func, ast.Attribute):
                    attr_chain = []
                    current = node.func
                    
                    while isinstance(current, ast.Attribute):
                        attr_chain.insert(0, current.attr)
                        current = current.value
                        
                    if isinstance(current, ast.Name):
                        base_obj = current.id
                        
                        # Common LLM API patterns
                        llm_patterns = [
                            {'obj': 'openai', 'methods': ['create', 'generate', 'complete']},
                            {'obj': 'client', 'methods': ['create', 'chat', 'complete']},
                            {'obj': 'anthropic', 'methods': ['create', 'complete', 'messages']}
                        ]
                        
                        for pattern in llm_patterns:
                            if base_obj == pattern['obj'] and any(m in attr_chain for m in pattern['methods']):
                                return True
                
                # Function names (e.g., generate_text, ask_llm)
                if isinstance(node.func, ast.Name):
                    llm_function_names = [
                        'chat', 'generate', 'complete', 'create_completion', 
                        'generate_text', 'ask_llm', 'query_llm'
                    ]
                    if node.func.id in llm_function_names:
                        return True
                        
                return False
                
        LLMCallVisitor().visit(node)
        return llm_calls
    
    def _has_unsanitized_path(self, param: str, llm_call: ast.Call, assignments: Dict[str, List[ast.AST]]) -> bool:
        """Check if there's an unsanitized path from param to llm_call."""
        # This is a simplified version - a full implementation would need 
        # to track data flow through the code more thoroughly
        
        # Direct use of the param in LLM call
        for arg in llm_call.args:
            if isinstance(arg, ast.Name) and arg.id == param:
                return True
                
        for kw in llm_call.keywords:
            if isinstance(kw.value, ast.Name) and kw.value.id == param:
                return True
        
        # TODO: In a full implementation, this would need to track variables
        # through assignments and function calls to find indirect paths
        
        return False
    
    def _get_location(self, node: ast.AST) -> Dict[str, Any]:
        """Get the location information for a node."""
        return {
            "line": getattr(node, "lineno", 0),
            "col": getattr(node, "col_offset", 0),
            "end_line": getattr(node, "end_lineno", 0),
            "end_col": getattr(node, "end_col_offset", 0)
        }
