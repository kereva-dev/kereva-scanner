import ast
import os
import re
import networkx as nx
from typing import List, Dict, Any, Optional, Set, Tuple, Union, Callable
from core.base_visitor import BaseVisitor
from core.ast_utils import extract_used_variables, get_attribute_chain, is_call_matching

class DataFlowAnalyzer(BaseVisitor):
    """
    Unified data flow analyzer for tracking various types of flow through code.
    
    This analyzer:
    1. Builds a data flow graph where nodes are variables/expressions and edges represent data flow
    2. Identifies source nodes (e.g., untrusted inputs, lists, sensitive data)
    3. Identifies sink nodes (e.g., LLM API calls, execution functions)
    4. Tracks transformations (e.g., string joins, format operations, sanitization)
    5. Analyzes the flow graph to find paths from sources to sinks
    
    This centralized analyzer can be used by multiple scanners including:
    - Taint analysis for security (user input -> LLM)
    - List tracking for performance (long lists -> prompts)
    - Data flow for privacy (sensitive data -> outputs)
    """
    
    def __init__(self, context: Dict[str, Any]):
        super().__init__(context)
        # Primary flow graph to track all data flow
        self.flow_graph = nx.DiGraph()
        
        # Source tracking (by type)
        self.sources = {
            'list': {},        # List variables
            'untrusted': {},   # Untrusted input variables
            'sensitive': {},   # Sensitive data variables
            'constant': {},    # String constants/templates
        }
        
        # Sink tracking
        self.sinks = {
            'llm': [],         # LLM API calls
            'execution': [],   # Code execution functions
            'output': [],      # Output functions
        }
        
        # Transformation tracking
        self.transformations = {}
        
        # Prompt variables (intermediary nodes)
        self.prompt_variables = {}
        
        # String templates and formatted strings
        self.string_templates = {}
        
        # Function/method aliases and wrappers
        self.function_aliases = {}
        
        # Flag for debug output
        self.debug = os.environ.get('DEBUG') == "1"
        
        # Transformation detection functions
        self.transform_detectors = [
            self._is_join_operation,
            self._is_format_method_call,
            self._is_template_render_call,
        ]
        
        # Patterns for various node types (from config)
        from core.config import LLM_API_PATTERNS, PROMPT_VARIABLE_PATTERNS
        self.llm_api_patterns = LLM_API_PATTERNS.copy()
        self.prompt_variable_patterns = PROMPT_VARIABLE_PATTERNS.copy()
        
        # Sanitization patterns for taint analysis
        self.sanitizers = []
        
        # Reported issues to avoid duplicates
        self.reported_issues = set()
        
    def visit_FunctionDef(self, node):
        """
        Process function definitions.
        - Identify wrapper functions
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
            self.function_aliases[node.name] = {
                'type': 'llm_wrapper',
                'line': node.lineno,
            }
            
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
        - Source variables (lists, user inputs, etc.)
        - Prompt variables
        - Flow between variables
        """
        # Let the base visitor track general variable assignments
        super().visit_Assign(node)
        
        # Only process simple assignments to a single variable
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            
            # Track this assignment in the flow graph
            self._add_assignment_to_graph(var_name, node)
            
            # Check if this is a list assignment
            self._check_list_assignment(var_name, node)
            
            # Check if this is a user input assignment
            self._check_input_assignment(var_name, node)
            
            # Check if this appears to be a prompt template variable
            if self._is_prompt_variable(var_name):
                self._track_prompt_variable(var_name, node)
                
            # Check if this is an LLM API call result
            if isinstance(node.value, ast.Call) and self._is_llm_api_call(node.value):
                self._process_llm_output(var_name, node.value)
    
    def visit_Call(self, node):
        """
        Track function calls, focusing on:
        - LLM API calls
        - String transformations (join, format)
        - Template rendering
        - Sanitization functions
        """
        # Let the base visitor process this node
        super().visit_Call(node)
        
        # Check if this is an LLM API call
        if self._is_llm_api_call(node):
            llm_node_id = f"llm_call_{getattr(node, 'lineno', 0)}"
            self.flow_graph.add_node(llm_node_id, type='sink', sink_type='llm', line=getattr(node, 'lineno', 0))
            self.sinks['llm'].append(node)
            
            # Process the inputs to this LLM call
            self._process_llm_call_inputs(node, llm_node_id)
        
        # Check for transformations
        for detector in self.transform_detectors:
            if detector(node):
                self._process_transformation(node, detector.__name__)
                break
        
        # Check for sanitization functions
        if self._is_sanitization_function(node):
            self._process_sanitization(node)
    
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
            
            # Check if the iterable is a known list source
            if iterable_var in self.sources['list']:
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
    
    def _add_assignment_to_graph(self, var_name: str, node: ast.Assign):
        """Add an assignment node to the flow graph with appropriate connections."""
        # Add variable node if it doesn't exist yet
        if var_name not in self.flow_graph:
            self.flow_graph.add_node(var_name, type='variable', line=node.lineno)
        
        # Connect used variables to this variable
        used_vars = extract_used_variables(node.value)
        for used_var in used_vars:
            self._add_flow_edge(used_var, var_name, 'assignment')
    
    def _check_list_assignment(self, var_name: str, node: ast.Assign):
        """Check if this assignment creates a list variable."""
        is_list = False
        list_length = None
        list_source = None
        
        if isinstance(node.value, ast.List):
            # Direct list literal
            is_list = True
            list_length = len(node.value.elts)
            list_source = "literal"
            
            if self.debug and list_length >= 10:  # Arbitrary threshold for debug
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
                if source_list in self.sources['list']:
                    # This list is derived from another list
                    list_length = self.sources['list'][source_list].get("length", "unknown")
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
        
        # If this is a list, add to our tracked list sources
        if is_list:
            self.sources['list'][var_name] = {
                "length": list_length,
                "source": list_source,
                "line": node.lineno,
                "node": node.value
            }
            
            # Add to flow graph as list source
            self.flow_graph.add_node(var_name, 
                                      type='source',
                                      source_type='list', 
                                      length=list_length,
                                      source=list_source,
                                      line=node.lineno)
    
    def _check_input_assignment(self, var_name: str, node: ast.Assign):
        """Check if this assignment comes from user input."""
        is_input = False
        input_source = None
        
        # Check for direct input() call
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id == 'input':
                is_input = True
                input_source = 'input'
            
            # Check for Flask/request-like patterns
            elif isinstance(node.value.func, ast.Attribute):
                attr_chain = get_attribute_chain(node.value.func)
                if attr_chain:
                    if 'request.form.get' in attr_chain or 'request.args.get' in attr_chain:
                        is_input = True
                        input_source = 'web_request'
        
        # If this is user input, add to tracked untrusted sources
        if is_input:
            self.sources['untrusted'][var_name] = {
                "source": input_source,
                "line": node.lineno,
                "node": node.value,
                "sanitized": False  # Initially not sanitized
            }
            
            # Add to flow graph as untrusted source
            self.flow_graph.add_node(var_name, 
                                      type='source', 
                                      source_type='untrusted',
                                      source=input_source,
                                      sanitized=False,
                                      line=node.lineno)
    
    def _track_prompt_variable(self, var_name: str, node: ast.Assign):
        """Track a variable that appears to be a prompt."""
        self.prompt_variables[var_name] = {
            "node": node.value,
            "line": node.lineno,
            "used_vars": extract_used_variables(node.value)
        }
        
        # Add to flow graph as prompt node
        if var_name in self.flow_graph:
            # Update existing node
            self.flow_graph.nodes[var_name]['is_prompt'] = True
        else:
            self.flow_graph.add_node(var_name, 
                                     type='variable', 
                                     is_prompt=True,
                                     line=node.lineno)
        
        # If this is a string constant, track it for template analysis
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self.string_templates[var_name] = {
                "content": node.value.value,
                "line": node.lineno,
                "placeholders": self._extract_placeholders(node.value.value)
            }
            
            # Add to flow graph as constant source
            self.sources['constant'][var_name] = {
                "content": node.value.value,
                "line": node.lineno
            }
            
            # Update node type to reflect it's a constant source
            self.flow_graph.nodes[var_name]['source_type'] = 'constant'
            self.flow_graph.nodes[var_name]['type'] = 'source'
                
        # Add flow edges from used variables to this prompt
        for used_var in extract_used_variables(node.value):
            self._add_flow_edge(used_var, var_name, 'direct_use')
    
    def _process_llm_output(self, var_name: str, call_node: ast.Call):
        """Process a variable that gets assigned the result of an LLM API call."""
        llm_node_id = f"llm_call_{call_node.lineno}"
        
        # Make sure the LLM call node exists
        if llm_node_id not in self.flow_graph:
            self.flow_graph.add_node(llm_node_id, 
                                    type='sink', 
                                    sink_type='llm', 
                                    line=call_node.lineno)
        
        # Connect LLM call to output variable
        self.flow_graph.add_edge(llm_node_id, var_name, type='llm_output')
        
        # Process inputs to this LLM call
        self._process_llm_call_inputs(call_node, llm_node_id)
    
    def _process_llm_call_inputs(self, node, llm_node_id):
        """Process the inputs to an LLM API call, adding flow graph connections."""
        # Check for keyword arguments like messages, content, prompt
        for kw in getattr(node, 'keywords', []):
            if kw.arg in ('messages', 'content', 'prompt', 'input'):
                # Special handling for OpenAI's message format
                if kw.arg == 'messages' and isinstance(kw.value, ast.List) and len(kw.value.elts) > 0:
                    for msg_dict in kw.value.elts:
                        if isinstance(msg_dict, ast.Dict):
                            for i, key in enumerate(msg_dict.keys):
                                if isinstance(key, ast.Constant) and key.value == 'content' and i < len(msg_dict.values):
                                    self._process_llm_input_arg(msg_dict.values[i], llm_node_id)
                else:
                    self._process_llm_input_arg(kw.value, llm_node_id)
        
        # Check positional arguments for common patterns
        for i, arg in enumerate(getattr(node, 'args', [])):
            # For common APIs, the first argument might be the prompt
            if i == 0 and isinstance(arg, (ast.Name, ast.Constant, ast.JoinedStr, ast.BinOp)):
                self._process_llm_input_arg(arg, llm_node_id)
    
    def _process_llm_input_arg(self, arg_node, llm_node_id):
        """Process a single argument to an LLM API call, tracing its data flow."""
        if isinstance(arg_node, ast.Name):
            # Direct variable reference
            var_name = arg_node.id
            # Add edge in flow graph from variable to LLM call
            self._add_flow_edge(var_name, llm_node_id, 'llm_input')
            
        elif isinstance(arg_node, ast.List):
            # List of message dictionaries or inputs
            for elt in arg_node.elts:
                if isinstance(elt, ast.Dict):
                    # Check content/text keys in dict
                    for i, key in enumerate(elt.keys):
                        if (isinstance(key, ast.Constant) and 
                            key.value in ('content', 'text') and 
                            i < len(elt.values)):
                            
                            # Process this dictionary value
                            self._process_llm_input_arg(elt.values[i], llm_node_id)
                elif isinstance(elt, (ast.Name, ast.Constant, ast.JoinedStr)):
                    # Process direct list elements
                    self._process_llm_input_arg(elt, llm_node_id)
                    
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
            
        elif isinstance(arg_node, ast.BinOp):
            # Binary operation (like string concatenation)
            left_vars = extract_used_variables(arg_node.left)
            right_vars = extract_used_variables(arg_node.right)
            
            # Create a special binop node
            binop_node_id = f"binop_{getattr(arg_node, 'lineno', 0)}"
            self.flow_graph.add_node(binop_node_id,
                                     type='transform',
                                     transform_type='binop',
                                     line=getattr(arg_node, 'lineno', 0))
            
            # Connect variables from both sides
            for var in left_vars:
                self._add_flow_edge(var, binop_node_id, 'binop_left')
            for var in right_vars:
                self._add_flow_edge(var, binop_node_id, 'binop_right')
                
            # Connect binop node to LLM call
            self.flow_graph.add_edge(binop_node_id, llm_node_id, type='llm_input')
            
        elif isinstance(arg_node, ast.Call):
            # This might be a transformation like join, format, etc.
            # First check if it's a join operation
            if self._is_join_operation(arg_node):
                # Process join specifically
                self._process_join_in_llm_arg(arg_node, llm_node_id)
            elif self._is_format_method_call(arg_node):
                # Process format specifically
                self._process_format_in_llm_arg(arg_node, llm_node_id)
            else:
                # Generic function call handling
                args_vars = []
                # Extract variables from positional args
                for arg in getattr(arg_node, 'args', []):
                    args_vars.extend(extract_used_variables(arg))
                # Extract variables from keyword args
                for kw in getattr(arg_node, 'keywords', []):
                    args_vars.extend(extract_used_variables(kw.value))
                
                # If we have used variables, add a function call node
                if args_vars:
                    func_node_id = f"func_{getattr(arg_node, 'lineno', 0)}"
                    self.flow_graph.add_node(func_node_id,
                                           type='transform',
                                           transform_type='function_call',
                                           line=getattr(arg_node, 'lineno', 0))
                    
                    # Connect variables to function
                    for var in args_vars:
                        self._add_flow_edge(var, func_node_id, 'function_arg')
                    
                    # Connect function to LLM call
                    self.flow_graph.add_edge(func_node_id, llm_node_id, type='llm_input')
    
    def _process_join_in_llm_arg(self, node, llm_node_id):
        """Process a join operation used directly in an LLM API call."""
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
            
            # Connect join directly to the LLM call
            self.flow_graph.add_edge(join_node_id, llm_node_id, type='llm_input')
    
    def _process_format_in_llm_arg(self, node, llm_node_id):
        """Process a format operation used directly in an LLM API call."""
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
        
        # Connect format directly to the LLM call
        self.flow_graph.add_edge(format_node_id, llm_node_id, type='llm_input')
    
    def _process_transformation(self, node, detector_name):
        """Process a transformation node (join, format, template) not directly in LLM context."""
        # Determine transformation type from detector name
        transform_type = detector_name.replace('_is_', '').replace('_call', '')
        
        # Handle join operation
        if transform_type == 'join_operation':
            self._process_join_operation(node)
        # Handle format method
        elif transform_type == 'format_method':
            self._process_format_call(node)
        # Handle template rendering
        elif transform_type == 'template_render':
            self._process_template_call(node)
    
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
        
        # Connect variables to template
        for var in template_vars:
            self._add_flow_edge(var, template_node_id, 'template_param')
        
        # Find parent assignment to track template result
        parent_var = self._find_parent_assignment(node)
        if parent_var:
            self._add_flow_edge(template_node_id, parent_var, 'transform_result')
    
    def _process_sanitization(self, node):
        """Process a sanitization function and mark variables as sanitized."""
        # Find input variable being sanitized
        input_var = None
        if len(node.args) > 0 and isinstance(node.args[0], ast.Name):
            input_var = node.args[0].id
        
        if not input_var:
            return
            
        # Create sanitization node
        sanitize_node_id = f"sanitize_{getattr(node, 'lineno', 0)}"
        self.flow_graph.add_node(
            sanitize_node_id,
            type='sanitize',
            line=getattr(node, 'lineno', 0)
        )
        
        # Connect input to sanitizer
        self._add_flow_edge(input_var, sanitize_node_id, 'sanitize_input')
        
        # Connect sanitizer to output (if available)
        parent_var = self._find_parent_assignment(node)
        if parent_var:
            self._add_flow_edge(sanitize_node_id, parent_var, 'sanitize_output')
            
            # Mark the output variable as sanitized
            if parent_var in self.flow_graph:
                self.flow_graph.nodes[parent_var]['sanitized'] = True
                
            # If it's in untrusted sources, mark it
            if parent_var in self.sources['untrusted']:
                self.sources['untrusted'][parent_var]['sanitized'] = True
    
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
    
    def _extract_placeholders(self, template: str) -> List[str]:
        """Extract placeholder names from a format string template."""
        if not template:
            return []
            
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
    
    def _find_parent_assignment(self, node) -> Optional[str]:
        """Try to find a parent assignment for an expression."""
        # Check if this node is used in any variable assignments we've tracked
        for var_name, data in self.prompt_variables.items():
            if data.get("node") == node:
                return var_name
        
        # This is a simplified implementation - a full one would need AST parent tracking
        # Unfortunately, without full AST parent tracking, this is limited
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
    
    def analyze_flow_paths(self, source_types=None, sink_types=None, cutoff=10):
        """
        Analyze the flow graph to find paths from source nodes to sink nodes.
        
        Args:
            source_types: List of source types to analyze (e.g., ['list', 'untrusted'])
            sink_types: List of sink types to analyze (e.g., ['llm', 'execution'])
            cutoff: Maximum path length to consider
            
        Returns:
            List of flow paths from sources to sinks
        """
        # Default to all source and sink types if none specified
        if source_types is None:
            source_types = list(self.sources.keys())
        if sink_types is None:
            sink_types = list(self.sinks.keys())
            
        if self.debug:
            print(f"Analyzing flow graph for paths from {source_types} to {sink_types}...")
            print(f"Graph has {len(self.flow_graph.nodes)} nodes and {len(self.flow_graph.edges)} edges")
        
        # Find all source nodes of the specified types
        source_nodes = []
        for source_type in source_types:
            for var_name in self.sources.get(source_type, {}):
                source_nodes.append(var_name)
        
        # Find all sink nodes of the specified types
        sink_nodes = []
        for node in self.flow_graph.nodes():
            if isinstance(node, str) and node.startswith(('llm_call_')):
                # Get node data
                node_data = self.flow_graph.nodes[node]
                if node_data.get('type') == 'sink' and node_data.get('sink_type') in sink_types:
                    sink_nodes.append(node)
                    
        if self.debug:
            print(f"Found {len(source_nodes)} source nodes and {len(sink_nodes)} sink nodes")
            
        # Store all paths found
        all_paths = []
        paths_found = 0
        
        # For each source, try to find paths to sinks
        for source_node in source_nodes:
            # Get source type and details
            source_type = None
            source_details = {}
            for stype, sources in self.sources.items():
                if source_node in sources:
                    source_type = stype
                    source_details = sources[source_node]
                    break
            
            if not source_type:
                continue
                
            # Filter sources if needed (e.g., skip short lists)
            if source_type == 'list':
                list_length = source_details.get("length", "unknown")
                if isinstance(list_length, int) and list_length < 10:  # Threshold
                    continue
                    
            # Check if untrusted input is already sanitized
            if source_type == 'untrusted' and source_details.get('sanitized', False):
                continue
                
            # Check paths to each sink
            for sink_node in sink_nodes:
                try:
                    # Find all simple paths from source to sink
                    paths = list(nx.all_simple_paths(self.flow_graph, source_node, sink_node, cutoff=cutoff))
                    
                    # If we found paths, collect them
                    if paths:
                        paths_found += len(paths)
                        
                        # Debug output
                        if self.debug:
                            print(f"Found {len(paths)} paths from {source_type} source '{source_node}' to sink '{sink_node}'")
                            for path in paths[:2]:  # Show just a couple paths
                                print(f"  Path: {' -> '.join(str(p) for p in path)}")
                        
                        # Add paths to results
                        for path in paths:
                            path_info = {
                                'source': source_node,
                                'source_type': source_type,
                                'source_details': source_details,
                                'sink': sink_node,
                                'sink_type': self.flow_graph.nodes[sink_node].get('sink_type', 'unknown'),
                                'path': path,
                                'path_string': ' -> '.join(str(p) for p in path),
                            }
                            all_paths.append(path_info)
                        
                except nx.NetworkXNoPath:
                    # No path exists
                    continue
                except Exception as e:
                    if self.debug:
                        print(f"Error analyzing path from {source_node} to {sink_node}: {str(e)}")
        
        if self.debug:
            print(f"Found {paths_found} total paths from {source_types} to {sink_types}")
            
        return all_paths
    
    # Helper methods for node type detection
    
    def _is_prompt_variable(self, var_name: str) -> bool:
        """Check if a variable name looks like it might be a prompt."""
        return any(pattern in var_name.lower() for pattern in self.prompt_variable_patterns)
    
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
            if self.debug:
                print(f"Detected LLM API call at line {getattr(node, 'lineno', 0)}")
            return True
        
        return False
    
    def _is_sanitization_function(self, node) -> bool:
        """Check if this is a sanitization function call."""
        sanitize_patterns = [
            # Common sanitization function names
            'sanitize', 'clean', 'escape', 'validate', 'filter',
            'html.escape', 'bleach.clean', 'strip_tags'
        ]
        
        if isinstance(node.func, ast.Name):
            if any(pattern in node.func.id for pattern in sanitize_patterns):
                return True
        
        elif isinstance(node.func, ast.Attribute):
            attr_chain = get_attribute_chain(node.func)
            if any(pattern in attr_chain for pattern in sanitize_patterns):
                return True
        
        return False