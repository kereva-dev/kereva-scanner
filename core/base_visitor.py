"""
Base Visitor Module

This module provides a base visitor class that scanners can extend.
It implements common visitor methods and state tracking.
"""

import ast
from typing import Dict, Any, Set, List, Optional, Callable

from core.ast_utils import (
    get_function_name, extract_string_value, extract_fstring_vars,
    extract_used_variables
)

class BaseVisitor(ast.NodeVisitor):
    """
    Base AST visitor with common functionality for scanners.
    
    Provides tracking for:
    - Variable assignments
    - Function calls
    - Imported modules
    - Class definitions
    - Function definitions
    
    This allows scanners to extend this visitor and focus on their specific
    logic while inheriting common state tracking.
    """
    
    def __init__(self, context: Optional[Dict[str, Any]] = None):
        self.context = context or {}
        
        # Track variable assignments for later reference
        self.variables = {}  # name -> {node, value, line, col}
        
        # Track all function calls
        self.function_calls = []  # list of Call nodes
        
        # Track imports and their aliases
        self.imports = {}  # module_name -> [alias1, alias2, ...]
        
        # Track defined classes
        self.classes = {}  # class_name -> ClassDef node
        
        # Track defined functions
        self.functions = {}  # function_name -> FunctionDef node
        
        # Track the current function being visited
        self.current_function = None
        
        # Track the current class being visited
        self.current_class = None
    
    def visit_Assign(self, node):
        """
        Process an assignment statement and track variables.
        """
        # Process all the targets
        for target in node.targets:
            # Simple variable assignment
            if isinstance(target, ast.Name):
                var_name = target.id
                string_value = extract_string_value(node.value)
                
                # Debug info if debug mode is enabled
                import os
                if os.environ.get('DEBUG') == "1":
                    print(f"BaseVisitor.visit_Assign: {var_name} = {type(node.value).__name__}")
                    print(f"  extracted string_value: {string_value}")
                
                self.variables[var_name] = {
                    "node": node,
                    "value": node.value,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "string_value": string_value
                }
            
            # Handle tuple assignments (a, b = 1, 2)
            elif isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple):
                for i, elt in enumerate(target.elts):
                    if isinstance(elt, ast.Name) and i < len(node.value.elts):
                        var_name = elt.id
                        value = node.value.elts[i]
                        self.variables[var_name] = {
                            "node": node,
                            "value": value,
                            "line": node.lineno,
                            "col": node.col_offset,
                            "string_value": extract_string_value(value)
                        }
        
        # Continue traversal
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """
        Process function calls and track them.
        """
        # Record the function call
        self.function_calls.append(node)
        
        # Call function handlers if defined by subclass
        func_name = get_function_name(node)
        if func_name:
            # Dispatches to handle_X methods if they exist
            handler_name = f"handle_{func_name.replace('.', '_')}"
            handler = getattr(self, handler_name, None)
            if handler and callable(handler):
                handler(node)
        
        # Continue traversal
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """
        Process import statements and track imported modules.
        """
        for name in node.names:
            module_name = name.name
            alias = name.asname or module_name
            
            if module_name not in self.imports:
                self.imports[module_name] = []
            
            if alias not in self.imports[module_name]:
                self.imports[module_name].append(alias)
        
        # Continue traversal
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """
        Process 'from import' statements and track imported objects.
        """
        module_name = node.module
        
        for name in node.names:
            import_name = name.name
            alias = name.asname or import_name
            
            # Track both the module and the imported object
            # For 'from module import object', we track both 'module' and 'module.object'
            if module_name:
                full_name = f"{module_name}.{import_name}"
                if full_name not in self.imports:
                    self.imports[full_name] = []
                
                if alias not in self.imports[full_name]:
                    self.imports[full_name].append(alias)
        
        # Continue traversal
        self.generic_visit(node)
    
    def visit_ClassDef(self, node):
        """
        Process class definitions and track them.
        """
        class_name = node.name
        self.classes[class_name] = node
        
        # Set current class context and reset after visiting
        previous_class = self.current_class
        self.current_class = class_name
        
        # Process the class body
        self.generic_visit(node)
        
        # Restore previous class context
        self.current_class = previous_class
    
    def visit_FunctionDef(self, node):
        """
        Process function definitions and track them.
        """
        function_name = node.name
        
        # If within a class, qualify the function name
        if self.current_class:
            qualified_name = f"{self.current_class}.{function_name}"
            self.functions[qualified_name] = node
        else:
            self.functions[function_name] = node
        
        # Set current function context and reset after visiting
        previous_function = self.current_function
        self.current_function = function_name
        
        # Process the function body
        self.generic_visit(node)
        
        # Restore previous function context
        self.current_function = previous_function
    
    def get_imported_modules(self, module_prefix: str) -> List[str]:
        """
        Get all imported modules that start with the given prefix.
        
        Args:
            module_prefix: The prefix to match against module names
            
        Returns:
            List of imported module names matching the prefix
        """
        return [
            module_name for module_name in self.imports
            if module_name.startswith(module_prefix)
        ]
    
    def is_module_imported(self, module_name: str) -> bool:
        """
        Check if a module has been imported.
        
        Args:
            module_name: The name of the module to check
            
        Returns:
            True if the module has been imported, False otherwise
        """
        return module_name in self.imports
    
    def get_variable_value(self, var_name: str) -> Optional[ast.AST]:
        """
        Get the value node for a variable if it exists.
        
        Args:
            var_name: The name of the variable to look up
            
        Returns:
            The value node for the variable or None if not found
        """
        if var_name in self.variables:
            return self.variables[var_name].get("value")
        return None
    
    def get_variable_string_value(self, var_name: str) -> Optional[str]:
        """
        Get the string value for a variable if it exists and is a string.
        
        Args:
            var_name: The name of the variable to look up
            
        Returns:
            The string value for the variable or None if not a string or not found
        """
        if var_name in self.variables:
            return self.variables[var_name].get("string_value")
        return None
    
    def get_function_by_name(self, func_name: str) -> Optional[ast.FunctionDef]:
        """
        Get a function definition by name.
        
        Args:
            func_name: The name of the function to look up
            
        Returns:
            The function definition node or None if not found
        """
        return self.functions.get(func_name)
    
    def get_class_by_name(self, class_name: str) -> Optional[ast.ClassDef]:
        """
        Get a class definition by name.
        
        Args:
            class_name: The name of the class to look up
            
        Returns:
            The class definition node or None if not found
        """
        return self.classes.get(class_name)