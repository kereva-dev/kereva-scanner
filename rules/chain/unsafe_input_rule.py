import ast
from typing import Any, Optional, Dict, List
from rules.base_rule import BaseRule
from core.issue import Issue
from core.config import UNTRUSTED_INPUT_PATTERNS, LLM_METHOD_CHAIN_PATTERNS, LLM_FUNCTION_NAMES

class UnsafeInputRule(BaseRule):
    """Rule to detect untrusted input flowing through LLM chains without sanitization."""
    
    def __init__(self):
        super().__init__(
            rule_id="chain-unsanitized-input",  # Fix: Changed to match the rule ID used in exclusion comments
            description="Untrusted input flows directly through LLM chain without sanitization",
            severity="high",
            tags=["security", "sanitization", "prompt-engineering"]
        )
        # Use untrusted input parameter names from config (can be customized through context)
        self.default_untrusted_params = UNTRUSTED_INPUT_PATTERNS
        
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
                            context={"param": param, "llm_call": ast.dump(llm_call)},
                            tags=self.tags
                        )
        elif isinstance(node_info, dict):
            # Handle vulnerability information from the analyzer
            if 'type' in node_info and node_info.get('type') == 'untrusted_to_llm':
                source = node_info.get('source', '')
                sink = node_info.get('sink', '')
                path = node_info.get('path', [])
                description = node_info.get('description', f"Untrusted input '{source}' flows to LLM API call without proper sanitization")
                
                # Get source code context and code snippet if available
                context = context or {}
                source_code = context.get('code', '')
                code_snippet = None
                lineno = node_info.get('line', 0)
                
                if source_code and lineno:
                    # Get up to 3 lines of context around the line of code
                    lines = source_code.split('\n')
                    start_line = max(0, lineno - 2)
                    end_line = min(len(lines), lineno + 1)
                    code_snippet = '\n'.join(lines[start_line:end_line])
                
                # Create more detailed context information
                issue_context = {
                    'source': source,
                    'sink': sink,
                    'path': ' -> '.join(str(p) for p in path) if path else '',
                    'code_snippet': code_snippet
                }
                
                return Issue(
                    rule_id=self.rule_id,
                    message=description,
                    location={
                        'file': context.get('file_name', '<unknown>'),
                        'line': lineno
                    },
                    severity=self.severity,
                    fix_suggestion="Implement input validation or use XML tag encapsulation for untrusted inputs",
                    context=issue_context,
                    tags=self.tags
                )
            
            # Handle prompt data dictionary from PromptScanner
            elif 'content' in node_info:
                # This rule doesn't need to do anything with this type of input
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
                        
                        # Use LLM method patterns from config
                        llm_patterns = LLM_METHOD_CHAIN_PATTERNS
                        
                        for pattern in llm_patterns:
                            if base_obj == pattern['obj'] and any(m in attr_chain for m in pattern['methods']):
                                return True
                
                # Function names (e.g., generate_text, ask_llm)
                if isinstance(node.func, ast.Name):
                    llm_function_names = LLM_FUNCTION_NAMES
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