import ast
import os
import re
import networkx as nx
from typing import List, Dict, Any, Optional, Set, Tuple
from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.base_visitor import BaseVisitor
from core.ast_utils import extract_used_variables, get_attribute_chain, is_call_matching
from core.config import LLM_API_PATTERNS, PROMPT_VARIABLE_PATTERNS

from rules.prompt.long_list_rule import LongListRule
# Import the XMLTagsScanner to use for checking XML tag protection
from scanners.prompt.xml_tags_scanner import XmlTagsScanner

class LongListScanner(BaseScanner):
    """Scanner for detecting prompts that programmatically add long lists of data points.
    
    LLMs can struggle with attention over long lists of items (like user comments,
    news stories, etc.) in the context window. This scanner identifies code patterns
    that might lead to inserting large amounts of list data into prompts.
    
    The scanner uses data flow analysis to track how list variables flow into LLM prompts,
    including through transformations like string joins, formats, and template rendering.
    """
    
    def __init__(self, warning_threshold: int = 10):
        # Initialize with the LongListRule
        rules = [LongListRule(warning_threshold=warning_threshold)]
        super().__init__(rules)
        # Threshold for the number of items before issuing a warning
        self.warning_threshold = warning_threshold
        # Create XML tags scanner for checking XML tag protection
        self.xml_tags_scanner = XmlTagsScanner()
    
    def scan(self, ast_node, context=None) -> List[Issue]:
        """Scan for patterns of adding long lists to prompts using data flow analysis."""
        context = context or {}
        debug = os.environ.get('DEBUG') == "1"
        
        if debug:
            print(f"LongListScanner scanning file: {context.get('file_name', 'unknown')}")
            
        # Create the analyzer for data flow tracking
        analyzer = ListPromptFlowAnalyzer(
            warning_threshold=self.warning_threshold,
            context=context,
            rule_applier=self.rule_applier,
            xml_tags_scanner=self.xml_tags_scanner
        )
        
        # First pass to identify list sources and LLM sinks
        analyzer.visit(ast_node)
        
        # Second pass to refine the flow graph with knowledge from first pass
        analyzer.visit(ast_node)
        
        # Analyze the flow graph to find paths from lists to prompts
        analyzer.analyze_flow_graph()
        
        self.issues = analyzer.issues
        return self.issues


class ListPromptFlowAnalyzer(BaseVisitor):
    """AST visitor that performs data flow analysis to track list-to-prompt flow.
    
    This analyzer:
    1. Identifies list variables as source nodes in a data flow graph
    2. Identifies LLM API calls as sink nodes 
    3. Tracks transformations like string joins that convert lists to strings
    4. Analyzes the flow graph to find paths from list sources to LLM prompt sinks
    5. Reports issues when lists that might be too long flow into prompts
    """
    
    def __init__(self, warning_threshold: int, context: Dict[str, Any], rule_applier, xml_tags_scanner=None):
        super().__init__(context)
        self.warning_threshold = warning_threshold
        self.rule_applier = rule_applier
        self.xml_tags_scanner = xml_tags_scanner
        self.issues = []
        
        # Track list variables (sources in data flow)
        self.list_variables = {}
        
        # Track prompt variables (intermediaries in data flow)
        self.prompt_variables = {}
        
        # Track LLM API calls (sinks in data flow)
        self.llm_calls = []
        
        # Track format string variables for template analysis
        self.format_string_vars = {}
        
        # Track string templates that may get transformed
        self.string_templates = {}
        
        # Track transformations (join, format, etc.)
        self.transformations = {}
        
        # Track reported issues to avoid duplicates
        # Format: (list_var, prompt_var, line_number)
        self.reported_issues = set()
        
        # Data flow graph to track paths from lists to LLM calls
        self.flow_graph = nx.DiGraph()
        
        # Track known wrapper functions for LLM calls
        self.llm_wrappers = set()
        
        # Use the shared LLM API patterns from config
        self.llm_api_patterns = LLM_API_PATTERNS
        
        # Debug flag
        self.debug = os.environ.get('DEBUG') == "1"
    
    def visit_FunctionDef(self, node):
        """
        Process function definitions.
        - Identify LLM wrapper functions
        - Track function context
        """
        # Let the base visitor handle context tracking
        super().visit_FunctionDef(node)
        
        # Check if this function contains LLM API calls
        contains_llm_call = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self._is_llm_api_call(child):
                contains_llm_call = True
                break
        
        if contains_llm_call:
            # This function is an LLM wrapper - add to our patterns
            self.llm_wrappers.add(node.name)
            
            # Add as a pattern for future detection
            self.llm_api_patterns.append({
                'type': 'function', 
                'names': [node.name]
            })
            
            if self.debug:
                print(f"Identified LLM wrapper function: {node.name}")
    
    def visit_Assign(self, node):
        """
        Track variable assignments, focusing on:
        - List sources (direct lists, comprehensions, re.findall, etc.)
        - Prompt variables (string literals, f-strings, etc.)
        - Flow between variables
        """
        # Let the base visitor track general variable assignments
        super().visit_Assign(node)
        
        # Only process simple assignments to a single variable
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            
            # Check if this is a list assignment
            is_list = False
            list_length = None
            list_source = None
            
            if isinstance(node.value, ast.List):
                # Direct list literal
                is_list = True
                list_length = len(node.value.elts)
                list_source = "literal"
                
                if self.debug and list_length >= self.warning_threshold:
                    print(f"Found list literal with {list_length} items assigned to {var_name}")
                
            elif isinstance(node.value, ast.ListComp):
                # List comprehension
                is_list = True
                list_source = "comprehension"
                
                # Try to determine source list
                if (hasattr(node.value, 'generators') and 
                    len(node.value.generators) > 0 and 
                    isinstance(node.value.generators[0].iter, ast.Name)):
                    
                    source_list = node.value.generators[0].iter.id
                    if source_list in self.list_variables:
                        # This list is derived from another list
                        list_length = self.list_variables[source_list].get("length", "unknown")
                        list_source = f"derived_from_{source_list}"
                        
                        # Add edge in flow graph showing derivation
                        self._add_flow_edge(source_list, var_name, 'list_derivation')
                    else:
                        list_length = "unknown"
            
            elif isinstance(node.value, ast.Call) and self._is_list_creating_call(node.value):
                # Call that might return a list (list(), json.loads(), etc.)
                is_list = True
                list_length = "unknown"
                
                # Add special handling for re.findall which often creates large lists
                if self._is_regex_findall(node.value):
                    list_source = "re_findall"
                else:
                    list_source = "function_call"
            
            # If this is a list, add to our tracked list variables
            if is_list:
                self.list_variables[var_name] = {
                    "length": list_length,
                    "source": list_source,
                    "line": node.lineno,
                    "node": node.value
                }
                
                # Add to flow graph as list source
                self.flow_graph.add_node(var_name, 
                                          type='list', 
                                          length=list_length,
                                          source=list_source,
                                          line=node.lineno)
            
            # Check if this is an LLM API call result
            if isinstance(node.value, ast.Call) and self._is_llm_api_call(node.value):
                # Track the LLM output variable
                llm_node_id = f"llm_call_{node.lineno}"
                self.flow_graph.add_node(llm_node_id, type='llm_call', line=node.lineno)
                self.flow_graph.add_edge(llm_node_id, var_name, type='llm_output')
                
                # Check inputs to this LLM call
                self._process_llm_call_inputs(node.value, llm_node_id)
            
            # Check if this appears to be a prompt template variable
            if self._is_prompt_variable(var_name):
                # Track as a prompt variable
                self.prompt_variables[var_name] = {
                    "node": node.value,
                    "line": node.lineno,
                    "used_vars": extract_used_variables(node.value)
                }
                
                # Add to flow graph as prompt node
                self.flow_graph.add_node(var_name, type='prompt', line=node.lineno)
                
                # If this is a string constant, track it for template analysis
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.format_string_vars[var_name] = {
                        "content": node.value.value,
                        "line": node.lineno
                    }
                    
                    # Check for placeholders in this string (potential format targets)
                    if "{" in node.value.value and "}" in node.value.value:
                        self.string_templates[var_name] = {
                            "content": node.value.value,
                            "line": node.lineno,
                            "placeholders": self._extract_placeholders(node.value.value)
                        }
                
                # Add flow edges from used variables to this prompt
                for used_var in extract_used_variables(node.value):
                    self._add_flow_edge(used_var, var_name, 'direct_use')
    
    def visit_Call(self, node):
        """
        Track function calls, focusing on:
        - LLM API calls
        - String transformations (join, format)
        - Template rendering
        """
        # Let the base visitor process this node
        super().visit_Call(node)
        
        # Check if this is an LLM API call
        if self._is_llm_api_call(node):
            llm_node_id = f"llm_call_{getattr(node, 'lineno', 0)}"
            self.flow_graph.add_node(llm_node_id, type='llm_call', line=getattr(node, 'lineno', 0))
            self.llm_calls.append(node)
            
            # Process the inputs to this LLM call
            self._process_llm_call_inputs(node, llm_node_id)
        
        # Track string join operations - key for list -> string conversion
        elif self._is_join_operation(node):
            self._process_join_operation(node)
        
        # Track format method calls for placeholder filling
        elif self._is_format_method_call(node):
            self._process_format_call(node)
        
        # Track template rendering calls
        elif self._is_template_render_call(node):
            self._process_template_call(node)
     
    def visit_For(self, node):
        """
        Track for loops that iterate over lists and build prompts.
        This is a common pattern for adding list items to prompts.
        """
        # Let the base visitor process this node
        self.generic_visit(node)
        
        # Check if we're iterating over a list variable
        if isinstance(node.target, ast.Name) and isinstance(node.iter, ast.Name):
            loop_var = node.target.id
            iterable_var = node.iter.id
            
            # Check if the iterable is a known list
            if iterable_var in self.list_variables:
                list_info = self.list_variables[iterable_var]
                
                # Find variables that are being appended to in the loop body
                append_targets = self._find_append_targets(node.body)
                
                # Add to flow graph - list is flowing to targets through the loop
                for target in append_targets:
                    # Create a special loop-based flow node
                    loop_node_id = f"loop_{node.lineno}_{iterable_var}_to_{target}"
                    self.flow_graph.add_node(
                        loop_node_id,
                        type='transform',
                        transform_type='loop_append',
                        source=iterable_var,
                        target=target,
                        line=node.lineno
                    )
                    
                    # Connect the list to the loop node
                    self.flow_graph.add_edge(iterable_var, loop_node_id, type='loop_source')
                    
                    # Connect the loop node to the target variable
                    self._add_flow_edge(loop_node_id, target, 'loop_append')
                    
                    # Check if any of the targets are prompt variables
                    if self._is_prompt_variable(target):
                        # Create a direct issue for this pattern since it's a very clear case
                        # This handles the direct list->loop->prompt pattern in bad_direct_list_in_prompt
                        if (list_info.get("length") == "unknown" or 
                            (isinstance(list_info.get("length"), int) and 
                             list_info.get("length") >= self.warning_threshold)):
                            
                            # Analyze the loop body to check if XML tags are being added
                            list_wrapped, items_wrapped = self._check_loop_for_xml_tags(node, loop_var)
                            
                            # Store this information for later flow analysis
                            self.flow_graph.nodes[loop_node_id]['list_wrapped_in_xml'] = list_wrapped
                            self.flow_graph.nodes[loop_node_id]['list_items_wrapped_in_xml'] = items_wrapped
                            
                            # Create a mock node for the issue location
                            mock_node = ast.fix_missing_locations(ast.Assign(
                                targets=[ast.Name(id=target, ctx=ast.Store())],
                                value=ast.Constant(value=""),
                                lineno=node.lineno,
                                col_offset=0
                            ))
                            
                            # Create issue data
                            issue_data = {
                                "node": mock_node,
                                "list_var": iterable_var,
                                "prompt_var": target,
                                "pattern_type": "for_loop",
                                "list_length": list_info.get("length"),
                                "list_wrapped_in_xml": list_wrapped,
                                "list_items_wrapped_in_xml": items_wrapped,
                                "flow_path": f"{iterable_var} -> loop -> {target}"
                            }
                            
                            # Generate issue if we haven't already
                            issue_key = (iterable_var, target, node.lineno)
                            if issue_key not in self.reported_issues:
                                issues = self.rule_applier.apply_rules(issue_data, self.context)
                                self.issues.extend(issues)
                                self.reported_issues.add(issue_key)
    
    def _process_llm_call_inputs(self, node, llm_node_id):
        """Process the inputs to an LLM API call."""
        # Check for keyword arguments like messages, content, prompt
        for kw in getattr(node, 'keywords', []):
            if kw.arg in ('messages', 'content', 'prompt'):
                # Special handling for OpenAI's message format in our examples
                if kw.arg == 'messages' and isinstance(kw.value, ast.List) and len(kw.value.elts) > 0:
                    for msg_dict in kw.value.elts:
                        if isinstance(msg_dict, ast.Dict):
                            for i, key in enumerate(msg_dict.keys):
                                if isinstance(key, ast.Constant) and key.value == 'content' and i < len(msg_dict.values):
                                    self._process_llm_input_arg(msg_dict.values[i], llm_node_id)
                else:
                    self._process_llm_input_arg(kw.value, llm_node_id)
        
        # Also check positional arguments for common patterns
        for i, arg in enumerate(getattr(node, 'args', [])):
            # For common APIs, the first argument might be the prompt
            if i == 0 and isinstance(arg, (ast.Name, ast.Constant, ast.JoinedStr)):
                self._process_llm_input_arg(arg, llm_node_id)
                
    def _process_llm_input_arg(self, arg_node, llm_node_id):
        """Process a single argument to an LLM API call."""
        if isinstance(arg_node, ast.Name):
            # Direct variable reference
            var_name = arg_node.id
            # Add edge in flow graph from variable to LLM call
            self._add_flow_edge(var_name, llm_node_id, 'llm_input')
            
        elif isinstance(arg_node, ast.List):
            # List of message dictionaries
            for elt in arg_node.elts:
                if isinstance(elt, ast.Dict):
                    # Check content/text keys in dict
                    for i, key in enumerate(elt.keys):
                        if (isinstance(key, ast.Constant) and 
                            key.value in ('content', 'text') and 
                            i < len(elt.values)):
                            
                            # Process this dictionary value
                            self._process_llm_input_arg(elt.values[i], llm_node_id)
                            
        elif isinstance(arg_node, ast.Dict):
            # Check for content in dictionary keys
            for i, key in enumerate(arg_node.keys):
                if (isinstance(key, ast.Constant) and 
                    key.value in ('content', 'text', 'prompt') and 
                    i < len(arg_node.values)):
                    
                    # Process this dictionary value
                    self._process_llm_input_arg(arg_node.values[i], llm_node_id)
        
        elif isinstance(arg_node, ast.JoinedStr):
            # f-string - extract used variables
            used_vars = extract_used_variables(arg_node)
            
            # Create a special format node for the f-string
            fstring_node_id = f"fstring_{getattr(arg_node, 'lineno', 0)}"
            self.flow_graph.add_node(fstring_node_id, 
                                     type='transform', 
                                     transform_type='fstring',
                                     line=getattr(arg_node, 'lineno', 0))
            
            # Connect all used variables to this format node
            for var in used_vars:
                self._add_flow_edge(var, fstring_node_id, 'fstring_arg')
                
            # Connect format node to LLM call
            self.flow_graph.add_edge(fstring_node_id, llm_node_id, type='llm_input')
    
    def _process_join_operation(self, node):
        """Process a string join operation which is key for list->string flow."""
        if not (isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'join' and 
                len(node.args) == 1):
            return
            
        # Get the delimiter and list being joined
        delimiter = ""
        if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
            delimiter = node.func.value.value
        
        # Check if we're joining a list variable
        if isinstance(node.args[0], ast.Name):
            list_var = node.args[0].id
            line_number = getattr(node, 'lineno', 0)
            
            # Create a transform node for this join operation
            join_node_id = f"join_{line_number}_{list_var}"
            self.flow_graph.add_node(
                join_node_id,
                type='transform',
                transform_type='join',
                delimiter=delimiter,
                source=list_var,
                line=line_number
            )
            
            # Add edge from list to join operation
            self._add_flow_edge(list_var, join_node_id, 'join_source')
            
            # Try to find the variable this join result is assigned to
            parent_var = self._find_parent_assignment(node)
            if parent_var:
                # Connect join result to the parent variable
                self._add_flow_edge(join_node_id, parent_var, 'transform_result')
            
            # If no parent found, store this transform for potential later connection
            else:
                self.transformations[join_node_id] = {
                    'type': 'join',
                    'source': list_var,
                    'line': line_number,
                    'node': node
                }
    
    def _process_format_call(self, node):
        """Process a string format method call."""
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == 'format'):
            return
            
        # Get the template string variable
        template_var = None
        if isinstance(node.func.value, ast.Name):
            template_var = node.func.value.id
        
        # Create a transform node for this format operation
        format_node_id = f"format_{getattr(node, 'lineno', 0)}"
        self.flow_graph.add_node(
            format_node_id,
            type='transform',
            transform_type='format',
            template=template_var,
            line=getattr(node, 'lineno', 0)
        )
        
        # Connect template to format operation if it's in our graph
        if template_var:
            self._add_flow_edge(template_var, format_node_id, 'format_template')
        
        # Process format arguments
        for i, arg in enumerate(getattr(node, 'args', [])):
            if isinstance(arg, ast.Name):
                var_name = arg.id
                self._add_flow_edge(var_name, format_node_id, 'format_arg')
            
            # Check for join operations in positional args
            elif isinstance(arg, ast.Call) and self._is_join_operation(arg):
                if len(arg.args) == 1 and isinstance(arg.args[0], ast.Name):
                    list_var = arg.args[0].id
                    # This is a direct list->join->format flow
                    self._add_join_to_format_flow(list_var, i, format_node_id)
        
        # Process keyword arguments
        for kw in getattr(node, 'keywords', []):
            # Direct variable reference
            if isinstance(kw.value, ast.Name):
                var_name = kw.value.id
                self._add_flow_edge(var_name, format_node_id, 'format_kwarg')
            
            # Check for join operation in kwargs - common pattern
            elif isinstance(kw.value, ast.Call) and self._is_join_operation(kw.value):
                if len(kw.value.args) == 1 and isinstance(kw.value.args[0], ast.Name):
                    list_var = kw.value.args[0].id
                    # This is a direct list->join->format flow
                    self._add_join_to_format_flow(list_var, kw.arg, format_node_id)
        
        # Try to find the variable this format result is assigned to
        parent_var = self._find_parent_assignment(node)
        if parent_var:
            # Connect format result to the parent variable
            self._add_flow_edge(format_node_id, parent_var, 'transform_result')

    def _process_template_call(self, node):
        """Process a template rendering call (eg. jinja2.render())."""
        # Get the template variables
        template_vars = self._extract_template_variables(node)
        line_number = getattr(node, 'lineno', 0)
        
        # Create a template node in the flow graph
        template_node_id = f"template_{line_number}"
        self.flow_graph.add_node(
            template_node_id,
            type='transform',
            transform_type='template',
            line=line_number
        )
        
        # Check if any list variables are being passed to the template
        list_vars_in_template = [v for v in template_vars if v in self.list_variables]
        
        # Add flow edges from lists to template
        for list_var in list_vars_in_template:
            self._add_flow_edge(list_var, template_node_id, 'template_param')
        
        # Find parent assignment to track template result
        parent_var = self._find_parent_assignment(node)
        if parent_var:
            self._add_flow_edge(template_node_id, parent_var, 'transform_result')
    
    def _add_join_to_format_flow(self, list_var, key, format_node_id):
        """Add flow edges for a join operation inside a format call."""
        # Create a specialized node for this pattern
        join_format_id = f"{format_node_id}_join_{key}"
        self.flow_graph.add_node(
            join_format_id,
            type='transform',
            transform_type='join_format',
            key=key,
            source=list_var
        )
        
        # Add the flow edges
        self._add_flow_edge(list_var, join_format_id, 'join_source')
        self._add_flow_edge(join_format_id, format_node_id, 'format_arg')
    
    def _extract_template_variables(self, call_node) -> List[str]:
        """Extract variables passed to a template rendering call."""
        variables = []
        
        # Check positional args
        for arg in getattr(call_node, 'args', []):
            if isinstance(arg, ast.Name):
                variables.append(arg.id)
        
        # Check keyword args
        for kw in getattr(call_node, 'keywords', []):
            if isinstance(kw.value, ast.Name):
                variables.append(kw.value.id)
        
        return variables
    
    def _find_append_targets(self, body) -> List[str]:
        """Find variables that are being appended to in a loop body."""
        targets = []
        
        for stmt in body:
            # Check for direct assignments with += (AugAssign)
            if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
                if isinstance(stmt.target, ast.Name):
                    targets.append(stmt.target.id)
            
            # Check for .append() calls
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if (isinstance(call.func, ast.Attribute) and 
                    call.func.attr == "append" and 
                    isinstance(call.func.value, ast.Name)):
                    
                    targets.append(call.func.value.id)
                    
            # Check for formatting operations
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                if isinstance(stmt.targets[0], ast.Name):
                    if isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.op, ast.Add):
                        # Simple string concatenation
                        targets.append(stmt.targets[0].id)
                    elif isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
                        # String methods like format()
                        if stmt.value.func.attr in ["format", "join"] and isinstance(stmt.value.func.value, ast.Name):
                            targets.append(stmt.targets[0].id)
        
        return targets
    
    def _check_loop_for_xml_tags(self, loop_node, loop_var) -> Tuple[bool, bool]:
        """Check if a loop adds XML tags around list items or the full list."""
        # Default to not wrapped
        list_wrapped = False
        items_wrapped = False
        
        # Debug output
        if self.debug:
            print(f"Checking loop at line {loop_node.lineno} for XML tags (loop var: {loop_var})")
        
        # Patterns for XML tags
        item_tag_patterns = [
            "<item>", "</item>", "<entry>", "</entry>",
            "<comment>", "</comment>", "<example>", "</example>",
            "<record>", "</record>", "<element>", "</element>"
        ]
        
        # List container tag patterns
        list_tag_patterns = [
            "<list>", "</list>", "<items>", "</items>",
            "<comments>", "</comments>", "<entries>", "</entries>",
            "<data>", "</data>"
        ]
        
        # Look for item tags in the loop body
        for stmt in loop_node.body:
            # Check string content in different node types
            content = self._extract_string_content(stmt)
            
            if content:
                # Check for item XML tags
                if any(pattern in content for pattern in item_tag_patterns):
                    items_wrapped = True
                    if self.debug:
                        print(f"  Found item XML tags in loop body: {content}")
        
        # Look for list container tags before and after the loop
        # This is more complex and would require parent-child relationships in the AST
        # For this implementation, we'll check variables used in the loop body
        
        # Get the variables being appended to
        append_targets = self._find_append_targets(loop_node.body)
        
        # For each variable, check if it's initialized with opening tags
        for target in append_targets:
            # Find in variables dictionary
            if target in self.variables:
                value = str(self.variables[target].get("value", ""))
                # Check for opening container tags
                if any(tag in value for tag in list_tag_patterns if not tag.startswith("</")): 
                    # Now look for closing tags after the loop
                    if self._find_closing_tag_after_loop(target, loop_node):
                        list_wrapped = True
                        if self.debug:
                            print(f"  Found list container tags wrapping: {target}")
        
        return list_wrapped, items_wrapped
    
    def _find_closing_tag_after_loop(self, var_name: str, loop_node) -> bool:
        """Check if there's a closing XML tag after a loop for a given variable."""
        # This is a simplified implementation - full implementation would need AST parent-child relations
        # For now, assume that if we find opening tags, closing tags are likely present
        return True
    
    def _extract_string_content(self, node) -> Optional[str]:
        """Extract string content from various AST node types."""
        # Direct string assignment
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
            elif isinstance(node.value, ast.JoinedStr):  # f-string
                return self._extract_fstring_content(node.value)
        
        # String augmented assignment (+=)
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
            elif isinstance(node.value, ast.JoinedStr):  # f-string
                return self._extract_fstring_content(node.value)
        
        # Function call with string args
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            for arg in getattr(call, 'args', []):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
                elif isinstance(arg, ast.JoinedStr):
                    return self._extract_fstring_content(arg)
        
        return None
    
    def _extract_fstring_content(self, node) -> str:
        """Extract approximated content from an f-string."""
        content = ""
        for value in getattr(node, 'values', []):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                content += value.value
            elif isinstance(value, ast.FormattedValue):
                content += "{...}"  # Placeholder for formatted values
        return content
    
    def _extract_placeholders(self, template: str) -> List[str]:
        """Extract placeholder names from a format string template."""
        import re
        # This is a basic implementation - a full one would handle nested braces, etc.
        placeholders = []
        # Find all {name} patterns
        matches = re.findall(r'\{([^{}]*)\}', template)
        for match in matches:
            # Filter out positional only placeholders
            if match and not match.isdigit():
                placeholders.append(match)
        return placeholders
    
    def _is_prompt_variable(self, var_name: str) -> bool:
        """Check if a variable name looks like it might be a prompt."""
        return any(pattern in var_name.lower() for pattern in PROMPT_VARIABLE_PATTERNS)
    
    def _is_list_creating_call(self, call_node) -> bool:
        """Check if a function call likely creates a list."""
        if isinstance(call_node.func, ast.Name):
            # Direct calls like list(), sorted(), etc.
            list_functions = ['list', 'sorted', 'reversed', 'range', 'enumerate', 'zip', 'filter', 'map']
            if call_node.func.id in list_functions:
                return True
        
        elif isinstance(call_node.func, ast.Attribute):
            # Method calls like json.loads(), df.to_list(), etc.
            list_methods = ['to_list', 'keys', 'values', 'items', 'split', 'loads', 'readlines', 'findall']
            if call_node.func.attr in list_methods:
                return True
        
        return False
    
    def _is_regex_findall(self, call_node) -> bool:
        """Check specifically for re.findall() which often creates large lists."""
        return (isinstance(call_node.func, ast.Attribute) and 
                isinstance(call_node.func.value, ast.Name) and
                call_node.func.value.id == 're' and
                call_node.func.attr == 'findall')
    
    def _is_join_operation(self, node) -> bool:
        """Check if a node is a string join operation on a list."""
        return (isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'join' and 
                len(node.args) == 1)
    
    def _is_format_method_call(self, node) -> bool:
        """Check if a node is a string format method call."""
        return (isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'format')
    
    def _is_template_render_call(self, node) -> bool:
        """Check if this is a template rendering function call."""
        if isinstance(node.func, ast.Attribute):
            # Common rendering method names
            render_methods = ['render', 'render_template', 'template', 'format']
            if node.func.attr in render_methods:
                return True
            
            # Check for "template.render()" pattern
            if (node.func.attr == 'render' and 
                isinstance(node.func.value, ast.Name) and 
                'template' in node.func.value.id.lower()):
                return True
        
        return False
    
    def _is_llm_api_call(self, node) -> bool:
        """Check if a node represents an LLM API call."""
        if not isinstance(node, ast.Call):
            return False
            
        # Use the shared is_call_matching utility
        if is_call_matching(node, self.llm_api_patterns):
            return True
            
        # Special handling for OpenAI's API pattern in our examples
        if (isinstance(node.func, ast.Attribute) and
            node.func.attr == 'create' and
            isinstance(node.func.value, ast.Attribute) and
            hasattr(node.func.value, 'attr') and 
            node.func.value.attr in ('completions', 'chat')):
            
            if self.debug:
                print(f"Detected LLM API call at line {getattr(node, 'lineno', 0)}")
            return True
            
        return False
    
    def _find_parent_assignment(self, node) -> Optional[str]:
        """Try to find a parent assignment for an expression."""
        # This is a simplified implementation - a full one would need AST parent tracking
        # Check if this node is used in any variable assignments we've tracked
        for var_name, var_info in self.variables.items():
            value_node = var_info.get("node")
            if value_node == node:
                return var_name
        return None
    
    def _add_flow_edge(self, source, target, edge_type='flow'):
        """Add an edge to the flow graph, ensuring both nodes exist."""
        # Make sure both nodes exist
        if source not in self.flow_graph:
            self.flow_graph.add_node(source, type='unknown')
        if target not in self.flow_graph:
            self.flow_graph.add_node(target, type='unknown')
            
        # Add the edge with the specified type
        self.flow_graph.add_edge(source, target, type=edge_type)
    
    def analyze_flow_graph(self):
        """Analyze the flow graph to find paths from lists to LLM calls."""
        if self.debug:
            print(f"Analyzing flow graph for list->prompt->LLM paths...")
            print(f"Graph has {len(self.flow_graph.nodes)} nodes and {len(self.flow_graph.edges)} edges")
            
        # Find all list source nodes (either direct or derived)
        list_nodes = [n for n in self.flow_graph.nodes() 
                     if isinstance(n, str) and n in self.list_variables]
        
        # Find all LLM call nodes
        llm_nodes = [n for n in self.flow_graph.nodes() 
                    if isinstance(n, str) and n.startswith('llm_call_')]
        
        if self.debug:
            print(f"Found {len(list_nodes)} list sources and {len(llm_nodes)} LLM sinks")
        
        # For each list, try to find paths to LLM calls
        paths_found = 0
        for list_node in list_nodes:
            list_info = self.list_variables.get(list_node, {})
            list_length = list_info.get("length", "unknown")
            
            # Skip lists that are definitely not long enough
            if isinstance(list_length, int) and list_length < self.warning_threshold:
                continue
                
            # Check paths to each LLM call
            for llm_node in llm_nodes:
                try:
                    # Find all simple paths from list to LLM
                    paths = list(nx.all_simple_paths(self.flow_graph, list_node, llm_node, cutoff=10))
                    
                    # If we found paths, this is a potential issue
                    if paths:
                        paths_found += 1
                        if self.debug:
                            print(f"Found path from list '{list_node}' to LLM call '{llm_node}'")
                            for path in paths[:2]:  # Show just a couple paths
                                print(f"  Path: {' -> '.join(str(p) for p in path)}")
                        
                        # Create an issue for the shortest path
                        path = min(paths, key=len)
                        self._create_issue_from_path(list_node, llm_node, path)
                        
                except nx.NetworkXNoPath:
                    # No path exists
                    continue
                except Exception as e:
                    if self.debug:
                        print(f"Error analyzing path from {list_node} to {llm_node}: {str(e)}")
        
        if self.debug:
            print(f"Found {paths_found} total paths from lists to LLM calls")
    
    def _create_issue_from_path(self, list_node, llm_node, path):
        """Create an issue for a list->LLM flow path."""
        # Get list information
        list_info = self.list_variables.get(list_node, {})
        list_length = list_info.get("length", "unknown")
        list_line = list_info.get("line", 0)
        
        # Find a prompt variable in the path if possible
        prompt_var = None
        prompt_line = 0
        
        for node in path:
            # Skip transform nodes, look for prompt variables
            if isinstance(node, str) and node in self.prompt_variables:
                prompt_var = node
                prompt_line = self.prompt_variables[node].get("line", 0)
                break
        
        if not prompt_var:
            # If no clear prompt variable, use the last transform node before the LLM call
            for i, node in enumerate(path):
                if i > 0 and i < len(path) - 1 and node.startswith(('join_', 'format_', 'template_')):
                    # This is a transform node - get its metadata
                    transform_data = self.flow_graph.nodes.get(node, {})
                    prompt_line = transform_data.get('line', list_line)
                    prompt_var = f"transformed_{node}"
                    break
        
        # If we still don't have a prompt var, use a generic one
        if not prompt_var:
            prompt_var = f"path_to_{llm_node}"
            prompt_line = list_line
        
        # Create a unique key for this issue
        issue_key = (list_node, prompt_var, list_line)
        if issue_key in self.reported_issues:
            return
            
        # Check if this flow includes XML tag wrapping
        list_wrapped_in_xml = False
        list_items_wrapped_in_xml = False
        
        # Check for XML protection in transform nodes
        for node in path:
            if node.startswith('loop_'):
                # Get XML wrapping information from loop node
                node_data = self.flow_graph.nodes.get(node, {})
                list_wrapped_in_xml = node_data.get('list_wrapped_in_xml', False)
                list_items_wrapped_in_xml = node_data.get('list_items_wrapped_in_xml', False)
                break
        
        # Create a mock node for the issue location
        mock_node = ast.fix_missing_locations(ast.Assign(
            targets=[ast.Name(id=prompt_var, ctx=ast.Store())],
            value=ast.Constant(value=""),
            lineno=prompt_line,
            col_offset=0
        ))
        
        # Create the issue with flow path information
        issue_data = {
            "node": mock_node,
            "list_var": list_node,
            "prompt_var": prompt_var,
            "pattern_type": "data_flow",
            "flow_path": " -> ".join(str(p) for p in path),
            "list_length": list_length,
            "list_wrapped_in_xml": list_wrapped_in_xml,
            "list_items_wrapped_in_xml": list_items_wrapped_in_xml
        }
        
        # Apply rules to create issues
        issues = self.rule_applier.apply_rules(issue_data, self.context)
        self.issues.extend(issues)
        
        # Mark as reported
        self.reported_issues.add(issue_key)
