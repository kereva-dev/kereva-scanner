import ast
import os
import networkx as nx
from typing import List, Dict, Set, Any, Optional

from scanners.base_scanner import BaseScanner
from core.issue import Issue

from core.prompt_fetcher import PromptFetcher
from rules.chain.langchain_rule import LangChainRule
from rules.prompt.xml_tags.langchain_rule import LangChainXMLTagRule


class LangChainScanner(BaseScanner):
    """Scanner for detecting LangChain-specific issues and vulnerabilities."""
    
    def __init__(self, offline_mode=False):
        # Initialize with appropriate rules
        rules = [
            LangChainXMLTagRule(),  # LangChain-specific XML tag rule
            LangChainRule()         # Rule for detecting LangChain-specific vulnerabilities
        ]
        super().__init__(rules)
        
        # Track state variable names that contain untrusted input
        self.untrusted_state_keys = [
            "question", "query", "input", "user_input", "human_input", 
            "message", "text", "request"
        ]
        # Track known LangChain hub prompts that might need XML tags
        self.known_hub_prompts = [
            "rlm/rag-prompt",
            "langchain/chat-prompt",
            "langchain/default-prompts"
        ]
        # Track common system command inputs that might be unsafe
        self.unsafe_sources = [
            "sys.argv", "request.args", "request.form", "request.json", 
            "input(", "raw_input("
        ]
        # Prompt fetching functionality
        self.offline_mode = offline_mode
        self.prompt_fetcher = PromptFetcher(offline_mode=offline_mode)
        
    def deduplicate_issues(self) -> None:
        """Remove duplicate issues based on rule_id, location, and message."""
        if not self.issues:
            return
        
        debug = os.environ.get('DEBUG') == "1"
        
        if debug:
            print(f"Deduplicating {len(self.issues)} issues")
            for i, issue in enumerate(self.issues):
                print(f"  Issue {i+1}: {issue.rule_id} at line {issue.location.get('line')} - {issue.message[:30]}...")
            
        unique_issues = {}
        
        # First compare rule_id with both 'langchain-xml-tags' and 'langchain-prompt-needs-xml-tags'
        # which are essentially the same
        xml_rule_ids = {'langchain-xml-tags', 'langchain-prompt-needs-xml-tags'}
        for issue in self.issues:
            # Handle duplicate XML tag rules by normalizing the rule_id
            normalized_rule_id = issue.rule_id
            if issue.rule_id in xml_rule_ids:
                normalized_rule_id = 'langchain-xml-tags'  # Normalize to one ID
                
            # Create a unique key based on rule_id, line, and file
            key = (
                normalized_rule_id,
                issue.location.get("line"),
                issue.location.get("file")
            )
            
            # Keep the one with the most detailed message
            if key in unique_issues:
                existing_len = len(unique_issues[key].message)
                new_len = len(issue.message)
                if new_len > existing_len:
                    unique_issues[key] = issue
            else:
                unique_issues[key] = issue
                
        # Replace the issues list with deduplicated issues
        old_count = len(self.issues)
        self.issues = list(unique_issues.values())
        new_count = len(self.issues)
        
        if debug:
            print(f"Deduplication: {old_count} issues reduced to {new_count}")
            for i, issue in enumerate(self.issues):
                print(f"  Issue {i+1}: {issue.rule_id} at line {issue.location.get('line')} - {issue.message[:30]}...")
    
    def scan(self, ast_tree, context=None) -> List[Issue]:
        """
        Scan LangChain code for potential issues.
        
        Args:
            ast_tree: The parsed AST tree
            context: Additional context information (file name, etc.)
            
        Returns:
            List of Issue objects
        """
        context = context or {}
        self.reset()  # Clear any previous issues
        
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print("\n== LangChainScanner.scan ==")
            print("Context:", context.keys())
        
        # Get code from context
        code = context.get("code", "")
        file_path = context.get("file_name", "<unknown>")
        self.offline_mode = context.get("offline_mode", self.offline_mode)
        
        if debug:
            print("File path:", file_path)
            print("Code length:", len(code))
            print("Code content (first 100 chars):", code[:100].replace('\n', '\\n'))
            print(f"Offline mode: {self.offline_mode}")
        
        # Update context with our scanning parameters
        context["untrusted_params"] = self.untrusted_state_keys
        context["known_hub_prompts"] = self.known_hub_prompts
        context["offline_mode"] = self.offline_mode
            
        # Apply rules directly to the AST
        self.apply_rules(ast_tree, context)
        
        # First check for unsafe patterns in the code directly
        self._scan_for_unsafe_input_patterns(file_path, code, self.issues)
        
        # Find and analyze LangChain hub prompts if not in offline mode
        if not self.offline_mode:
            self._analyze_langchain_hub_prompts(ast_tree, file_path, self.issues)
        
        # Then use the AST analyzer for more complex patterns
        analyzer = LangChainAnalyzer(self.untrusted_state_keys, self.known_hub_prompts)
        analyzer.current_tree = ast_tree  # Set the current tree for reference
        analyzer.offline_mode = self.offline_mode
        analyzer.visit(ast_tree)
        
        # Process identified vulnerabilities from the analyzer
        for vuln in analyzer.vulnerabilities:
            issue = Issue(
                rule_id=vuln["rule_id"],
                severity=vuln["severity"],
                message=vuln["message"],
                fix_suggestion=vuln["suggestion"],
                context=vuln.get("context", {}),
                location={"line": vuln.get("line", 0), "file": file_path}
            )
            self.register_issue(issue)
            
        # Deduplicate issues
        self.deduplicate_issues()
            
        if debug:
            print(f"Final count of issues: {len(self.issues)}")
            
        return self.issues
        
    def _scan_for_unsafe_input_patterns(self, filepath, code, issues):
        """Scan the code directly for unsafe input patterns."""
        lines = code.split('\n')
        
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print("\nLangChainScanner analyzing file:", filepath)
            print("File content length:", len(code))
            print("Lines:", len(lines))
        
        # Track important patterns
        has_sys_argv = False
        sys_argv_line = 0
        has_graph_invoke = False
        graph_invoke_line = 0
        has_rag_prompt = False
        rag_prompt_line = 0
        
        # First pass to identify key patterns
        for i, line in enumerate(lines):
            line_num = i + 1
            
            if "sys.argv" in line:
                has_sys_argv = True
                sys_argv_line = line_num
                if debug:
                    print(f"Found sys.argv at line {line_num}: {line.strip()}")
            
            if "graph.invoke" in line and "question" in line:
                has_graph_invoke = True
                graph_invoke_line = line_num
                if debug:
                    print(f"Found graph.invoke with question at line {line_num}: {line.strip()}")
                
            if "hub.pull" in line and "rlm/rag-prompt" in line:
                has_rag_prompt = True
                rag_prompt_line = line_num
                if debug:
                    print(f"Found rlm/rag-prompt at line {line_num}: {line.strip()}")
                
        if debug:
            print(f"Pattern summary - sys.argv: {has_sys_argv}, graph.invoke: {has_graph_invoke}, rag_prompt: {has_rag_prompt}")
        
        # Now analyze the patterns we found
        if has_sys_argv and has_graph_invoke:
            # This is a pattern where user input flows to the LLM through the graph
            self.register_issue(Issue(
                rule_id="chain-langchain-unsanitized-user-input",
                severity="high",
                message="Command line input from sys.argv flows to LLM without proper sanitization",
                fix_suggestion="Implement input validation before using user input in the LangChain graph",
                context={"sys_argv_line": sys_argv_line, "graph_invoke_line": graph_invoke_line},
                location={"line": sys_argv_line, "file": filepath}
            ))
            
        # We don't need to analyze hub prompts in _scan_for_unsafe_input_patterns
        # Just remove the hub prompt detection logic from here
        
        # Reset rag_prompt processing flag since we handle it separately
        has_rag_prompt = False
                
        # Check for specific patterns in the code
        for i, line in enumerate(lines):
            line_num = i + 1
            
            # Look for direct passing of user input to prompt templates
            if "messages = prompt.invoke" in line or "prompt.invoke" in line:
                # Check for dictionary with questions
                if "{" in line and "}" in line and "question" in line:
                    # This might be passing a question directly
                    # Look for sanitization in preceding lines
                    sanitized = False
                    for j in range(max(0, i-10), i):
                        if "sanitize" in lines[j] or "validate" in lines[j] or "clean" in lines[j]:
                            sanitized = True
                            break
                            
                    if not sanitized:
                        self.register_issue(Issue(
                            rule_id="chain-langchain-template-injection",
                            severity="medium",
                            message="Template variables passed to LangChain prompt without sanitization",
                            fix_suggestion="Sanitize inputs before passing them to prompt templates",
                            context={"line_content": line.strip()},
                            location={"line": line_num, "file": filepath}
                        ))
            
            # Also check direct graph invocation with raw input
            if "graph.invoke" in line and "{" in line and "}" in line and "question" in line:
                # There's a graph invocation passing a question directly
                # Check if we've sanitized it
                sanitized = False
                for j in range(max(0, i-10), i):
                    if "sanitize" in lines[j] or "validate" in lines[j] or "clean" in lines[j]:
                        sanitized = True
                        break
                        
                # If there's evidence of sys.argv earlier, and no sanitization
                if has_sys_argv and not sanitized:
                    self.register_issue(Issue(
                        rule_id="chain-langchain-rag-injection",
                        severity="high",
                        message="User input from command line passed to LangChain RAG without sanitization",
                        fix_suggestion="Sanitize user input before passing it to the LangChain graph",
                        context={"line_content": line.strip()},
                        location={"line": line_num, "file": filepath}
                    ))


    def _analyze_langchain_hub_prompts(self, ast_tree, file_path, issues):
        """
        Find and analyze LangChain hub prompts by fetching their templates.
        
        Args:
            ast_tree: The parsed AST tree
            file_path: Path to the analyzed file
            issues: List of issues to append to
        """
        debug = os.environ.get('DEBUG') == "1"
        
        if debug:
            print(f"Analyzing LangChain hub prompts in file: {file_path}")
            
        hub_calls = self._find_hub_pull_calls(ast_tree)
        
        if not hub_calls:
            if debug:
                print(f"No hub.pull() calls found in file")
            return
            
        if debug:
            print(f"Found {len(hub_calls)} hub.pull() calls")
        
        # Track analyzed prompts to avoid duplicates
        analyzed_prompts = set()
        
        for line_num, prompt_id in hub_calls:
            if debug:
                print(f"Processing hub prompt: {prompt_id} at line {line_num}")
            
            # Skip if not a known prompt that we should check or if already analyzed
            if prompt_id not in self.known_hub_prompts or prompt_id in analyzed_prompts:
                continue
                
            # Mark as analyzed
            analyzed_prompts.add(prompt_id)
                
            # Fetch the prompt from LangChain Hub
            prompt_data = self.prompt_fetcher.fetch_langchain_hub_prompt(prompt_id)
            
            if not prompt_data:
                # If fetching failed, use a heuristic approach
                self.register_issue(Issue(
                    rule_id="prompt-langchain-needs-xml-tags",
                    severity="medium",
                    message=f"LangChain hub prompt '{prompt_id}' should use XML tags for template variables",
                    fix_suggestion="Modify the prompt template to wrap variables in XML tags like <variable>",
                    context={"prompt_id": prompt_id},
                    location={"line": line_num, "file": file_path}
                ))
                continue
                
            # Check if the prompt template uses XML tags
            template = prompt_data.get("content", "")
            variables = prompt_data.get("variables", [])
            
            if not self.prompt_fetcher.has_xml_tags(template) and variables:
                # Create a synthetic prompt node to apply the XML tag rule through the rule framework
                prompt_data_dict = {
                    "content": template,
                    "line": line_num,
                    "is_template": True,
                    "template_variables": variables
                }
                
                # Apply rules to the prompt data (the LangChainXMLTagRule will handle this)
                context = {
                    "file_name": file_path, 
                    "hub_prompt": True,
                    "prompt_id": prompt_id
                }
                
                self.apply_rules(
                    prompt_data_dict, 
                    context,
                    filter_func=lambda rule: rule.rule_id == "prompt-langchain-xml-tags"
                )
    
    def _find_hub_pull_calls(self, ast_tree):
        """
        Find all hub.pull() calls in the AST.
        
        Returns:
            List of (line_number, prompt_id) tuples
        """
        hub_calls = []
        
        class HubPullFinder(ast.NodeVisitor):
            def visit_Call(self, node):
                prompt_id = self.prompt_fetcher.extract_prompt_id_from_node(node)
                if prompt_id:
                    hub_calls.append((getattr(node, 'lineno', 0), prompt_id))
                self.generic_visit(node)
                
        finder = HubPullFinder()
        finder.prompt_fetcher = self.prompt_fetcher
        finder.visit(ast_tree)
        
        return hub_calls


class LangChainAnalyzer(ast.NodeVisitor):
    """Analyzes LangChain code for security vulnerabilities and best practices."""
    
    def __init__(self, untrusted_keys, known_hub_prompts):
        self.untrusted_keys = untrusted_keys
        self.known_hub_prompts = known_hub_prompts
        self.vulnerabilities = []
        self.flow_graph = nx.DiGraph()
        self.state_variables = {}  # Track StateGraph state dictionaries
        self.hub_prompts = {}  # Track hub.pull() calls
        self.llm_instances = {}  # Track LLM instances
        self.active_state_key = None  # Current state key being analyzed
        self.state_class = {}  # Store state class definitions
        self.current_tree = None  # Track the current AST tree
        self.offline_mode = False  # Whether we're running in offline mode
        
        # Track analyzed prompts to avoid duplicates
        self.analyzed_prompts = set()
        
    def visit_Assign(self, node):
        """Track variable assignments to identify state objects and LLM instances."""
        # Check for LLM initialization
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            
            # Check for LLM initialization
            if isinstance(node.value, ast.Call):
                if self._is_llm_initialization(node.value):
                    self.llm_instances[var_name] = {
                        "line": node.lineno,
                        "type": self._get_llm_type(node.value)
                    }
                    
                # Check for hub.pull() calls
                elif self._is_hub_pull(node.value):
                    prompt_id = self._extract_hub_prompt_id(node.value)
                    if prompt_id:
                        # Track variable assignment
                        self.hub_prompts[var_name] = {
                            "id": prompt_id,
                            "line": node.lineno,
                            "needs_xml_tags": self._check_prompt_needs_tags(prompt_id)
                        }
                        
                        # Skip XML tag warnings here since those are handled by _analyze_langchain_hub_prompts
                        # and we don't want to duplicate the warnings
        
        self.generic_visit(node)
        
    def visit_FunctionDef(self, node):
        """Analyze LangChain state processing functions."""
        # Check if this is a state processor function (takes a state parameter)
        if len(node.args.args) > 0 and hasattr(node.args.args[0], 'annotation'):
            if isinstance(node.args.args[0].annotation, ast.Name):
                state_type = node.args.args[0].annotation.id
                if state_type == "State":
                    # This is a state processor function, analyze for state access
                    state_param = node.args.args[0].arg
                    self.active_state_key = state_param
                    
                    # Find all subscripts accessing state keys
                    state_reads, state_writes = self._find_state_accesses(node, state_param)
                    
                    # Check for untrusted input flowing to dangerous operations
                    for read_key in state_reads:
                        if read_key in self.untrusted_keys:
                            for write_key in state_writes:
                                # If we're taking untrusted input and not sanitizing it
                                if not self._has_sanitization(node, read_key):
                                    self.vulnerabilities.append({
                                        "rule_id": "chain-langchain-unsanitized-state-flow",
                                        "severity": "high",
                                        "message": f"Untrusted input from state['{read_key}'] flows to state['{write_key}'] without sanitization",
                                        "suggestion": "Implement input validation or sanitization before using untrusted input in LLM context",
                                        "line": node.lineno,
                                        "context": {
                                            "source": read_key,
                                            "sink": write_key,
                                            "function": node.name
                                        }
                                    })
        
        self.generic_visit(node)
        self.active_state_key = None
        
    def visit_ClassDef(self, node):
        """Process class definitions to identify State classes."""
        # Check if this is a TypedDict class (LangChain state definition)
        is_typed_dict = False
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == "TypedDict":
                is_typed_dict = True
                
        if is_typed_dict:
            self.state_class[node.name] = {"keys": []}
            
            # Extract all keys defined in the TypedDict
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    self.state_class[node.name]["keys"].append(stmt.target.id)
        
        self.generic_visit(node)
        
    def visit_Call(self, node):
        """Detect LLM invocations and prompt usages."""
        # Check for LLM invoke calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "invoke":
            if isinstance(node.func.value, ast.Name) and node.func.value.id in self.llm_instances:
                # This is a llm.invoke() call, check its arguments
                llm_name = node.func.value.id
                
                # Check if untrusted user input is flowing into the LLM
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in self.state_variables:
                        self.vulnerabilities.append({
                            "rule_id": "chain-langchain-unsanitized-llm-input",
                            "severity": "high",
                            "message": f"Directly passing potentially untrusted state variable '{arg.id}' to LLM",
                            "suggestion": "Implement input validation before passing state variables to LLM calls",
                            "line": node.lineno,
                            "context": {
                                "llm": llm_name,
                                "variable": arg.id
                            }
                        })
            
            # Check for prompt template invocations
            elif isinstance(node.func.value, ast.Name) and node.func.value.id in self.hub_prompts:
                prompt_var = node.func.value.id
                prompt_info = self.hub_prompts[prompt_var]
                
                # Check if we're passing untrusted input to the prompt
                if len(node.keywords) > 0:
                    for kw in node.keywords:
                        if kw.arg in self.untrusted_keys:
                            # Using untrusted input in a prompt template
                            self.vulnerabilities.append({
                                "rule_id": "chain-langchain-prompt-template-injection",
                                "severity": "high",
                                "message": f"Untrusted input '{kw.arg}' used in prompt template '{prompt_info['id']}' without XML tags",
                                "suggestion": "Use XML tags to wrap variables in the prompt template",
                                "line": node.lineno,
                                "context": {
                                    "prompt_id": prompt_info["id"],
                                    "variable": kw.arg
                                }
                            })
        
        # Check for StateGraph construction
        elif isinstance(node.func, ast.Name) and node.func.id == "StateGraph":
            if len(node.args) > 0 and isinstance(node.args[0], ast.Name):
                state_type = node.args[0].id
                self.state_variables[state_type] = {
                    "line": node.lineno,
                    "untrusted_keys": []
                }
                
                # Find all keys defined in the state class
                state_keys = self._find_state_class_keys(state_type)
                for key in state_keys:
                    if key in self.untrusted_keys:
                        self.state_variables[state_type]["untrusted_keys"].append(key)
        
        # Check for user input directly passed to invoke
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "invoke":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "graph":
                # This is likely the final graph.invoke() call
                if len(node.args) > 0 and isinstance(node.args[0], ast.Dict):
                    # Check dictionary keys for untrusted input
                    for i, key in enumerate(node.args[0].keys):
                        if isinstance(key, ast.Str) and key.s in self.untrusted_keys:
                            value = node.args[0].values[i]
                            if self._is_untrusted_source(value):
                                self.vulnerabilities.append({
                                    "rule_id": "chain-langchain-unsanitized-graph-input",
                                    "severity": "high", 
                                    "message": f"Untrusted input directly passed to graph through key '{key.s}'",
                                    "suggestion": "Sanitize user input before passing to the LangChain graph",
                                    "line": node.lineno,
                                    "context": {
                                        "key": key.s,
                                        "source": self._get_source_name(value)
                                    }
                                })
        
        # Specifically avoid visiting hub.pull() calls here - those are handled by _analyze_langchain_hub_prompts
        elif not (isinstance(node.func, ast.Attribute) and 
                 node.func.attr == "pull" and 
                 isinstance(node.func.value, ast.Name) and 
                 node.func.value.id == "hub"):
            self.generic_visit(node)
        else:
            # Skip further processing of hub.pull calls to avoid duplicates
            pass
    
    def _is_llm_initialization(self, node):
        """Check if a call node is initializing an LLM."""
        if isinstance(node.func, ast.Name):
            return node.func.id in ["init_chat_model", "ChatOpenAI", "ChatAnthropic"]
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return node.func.value.id in ["openai", "anthropic", "langchain"]
        return False
    
    def _get_llm_type(self, node):
        """Extract the type of LLM being initialized."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{node.func.value.id}.{node.func.attr}"
        return "unknown"
    
    def _is_hub_pull(self, node):
        """Check if a call node is a hub.pull() call."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "pull":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hub":
                return True
        return False
    
    def _extract_hub_prompt_id(self, node):
        """Extract the prompt ID from a hub.pull() call."""
        if len(node.args) > 0 and isinstance(node.args[0], ast.Str):
            return node.args[0].s
        return None
    
    def _check_prompt_needs_tags(self, prompt_id):
        """Check if a prompt should use XML tags based on its ID."""
        # This is a heuristic - in a real implementation, you might want to 
        # fetch the actual prompt template and analyze it
        return prompt_id in self.known_hub_prompts
    
    def _find_state_accesses(self, func_node, state_param):
        """Find all state dictionary accesses in a function."""
        state_reads = set()
        state_writes = set()
        
        class StateAccessVisitor(ast.NodeVisitor):
            def __init__(self, state_param, reads, writes):
                self.state_param = state_param
                self.reads = reads
                self.writes = writes
                
            def visit_Subscript(self, node):
                # Check if this is accessing the state dictionary
                if isinstance(node.value, ast.Name) and node.value.id == self.state_param:
                    # Extract the key
                    if isinstance(node.slice, ast.Str):
                        key = node.slice.s
                    elif isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                        key = node.slice.value
                    else:
                        # Can't determine key statically
                        return
                    
                    # Determine if this is a read or write
                    # Look for parent nodes to determine context
                    for parent in ast.walk(func_node):
                        for field, value in ast.iter_fields(parent):
                            if isinstance(value, list) and node in value:
                                # Parent contains this node in a list
                                if isinstance(parent, ast.Assign) and node in parent.targets:
                                    self.writes.add(key)
                                else:
                                    self.reads.add(key)
                            elif value == node:
                                # Parent directly contains this node
                                if isinstance(parent, ast.Assign) and parent.targets[0] == node:
                                    self.writes.add(key)
                                else:
                                    self.reads.add(key)
                
                self.generic_visit(node)
        
        visitor = StateAccessVisitor(state_param, state_reads, state_writes)
        visitor.visit(func_node)
        
        return state_reads, state_writes
    
    def _has_sanitization(self, func_node, key):
        """
        Check if there's any sanitization for the given key in the function.
        This is a simplistic check - a real implementation would be more sophisticated.
        """
        # Look for common sanitization patterns
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ["sanitize", "validate", "clean"]:
                    return True
        return False
    
    def _find_state_class_keys(self, class_name):
        """Find all keys defined in a State TypedDict class."""
        keys = []
        if class_name in self.state_class:
            return self.state_class[class_name].get("keys", [])
        
        # If not found in our tracked state classes, look through the AST
        current_tree = self.current_tree if hasattr(self, "current_tree") else None
        if current_tree:
            for node in ast.walk(current_tree):
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    for stmt in node.body:
                        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                            keys.append(stmt.target.id)
        return keys
    
    def _is_untrusted_source(self, node):
        """Check if a node represents an untrusted input source."""
        if isinstance(node, ast.Name):
            # Variable names that suggest user input
            return node.id in self.untrusted_keys
        elif isinstance(node, ast.Attribute):
            # Common input sources like request.form, etc.
            return node.attr in ["form", "args", "params", "input", "data"]
        elif isinstance(node, ast.Subscript):
            # Check for list/dict access to sys.argv
            if isinstance(node.value, ast.Attribute) and node.value.attr == "argv":
                if isinstance(node.value.value, ast.Name) and node.value.value.id == "sys":
                    return True
        return False
    
    def _get_source_name(self, node):
        """Get a string representation of an input source."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "argv":
                if isinstance(node.value.value, ast.Name) and node.value.value.id == "sys":
                    return "sys.argv[]"
        return "unknown"