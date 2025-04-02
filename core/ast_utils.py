"""
AST Utilities Module

This module provides common utility functions for working with Python AST (Abstract Syntax Tree) nodes.
It centralizes frequently used operations to avoid code duplication across scanners and rules.

It also includes utilities for working with code content and improving issue reporting accuracy.
"""

import ast
import os
import re
import tokenize
from io import StringIO
from typing import List, Dict, Any, Optional, Set, Tuple, Union, Callable, TypeVar, Type, Mapping


# ===== Node Traversal =====

def get_parent_node(node: ast.AST, tree: ast.AST) -> Optional[ast.AST]:
    """
    Find the parent node of a given node in an AST.
    
    Args:
        node: The node to find the parent for
        tree: The root of the AST to search in
        
    Returns:
        The parent node if found, None otherwise
    """
    class ParentFinder(ast.NodeVisitor):
        def __init__(self, target):
            self.target = target
            self.parent = None
            
        def generic_visit(self, node):
            for field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST):
                            if item == self.target:
                                self.parent = node
                            else:
                                self.visit(item)
                elif isinstance(value, ast.AST):
                    if value == self.target:
                        self.parent = node
                    else:
                        self.visit(value)
    
    finder = ParentFinder(node)
    finder.visit(tree)
    return finder.parent


# ===== Name Resolution =====

def get_function_name(node: ast.Call) -> Optional[str]:
    """
    Extract the full function name from a Call node.
    
    Handles both simple names (func_name) and attribute chains (module.class.method).
    
    Args:
        node: The AST Call node
    
    Returns:
        A string representation of the function name, or None if not resolvable
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def get_attribute_chain(node: ast.AST) -> List[str]:
    """
    Get the attribute chain from an Attribute node.
    
    For example, obj.attr1.attr2 would return ['obj', 'attr1', 'attr2']
    
    Args:
        node: An AST node, typically an Attribute node
        
    Returns:
        List of attribute names in the chain
    """
    if isinstance(node, ast.Name):
        return [node.id]
    
    if not isinstance(node, ast.Attribute):
        return []
        
    parts = []
    current = node
    
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
        
    if isinstance(current, ast.Name):
        parts.append(current.id)
    
    return list(reversed(parts))


def follow_param_path(call_node: ast.Call, path: List[Union[str, int]]) -> Optional[ast.AST]:
    """
    Follow a parameter path in a function call.
    
    Args:
        call_node: The function call node
        path: A list of parameter names or indices to follow
    
    Returns:
        The AST node at the end of the path, or None if the path doesn't exist
    """
    if not path:  # Empty path means we're already at the target
        return call_node
            
    # Handle positional arguments
    if isinstance(path[0], int) and path[0] < len(call_node.args):
        current = call_node.args[path[0]]
        path = path[1:]
    # Handle keyword arguments
    else:
        for kw in call_node.keywords:
            if kw.arg == path[0]:
                current = kw.value
                path = path[1:]
                break
        else:
            return None
    
    # Follow the rest of the path
    for step in path:
        if isinstance(current, ast.Dict) and isinstance(step, str):
            # Find the key in the dict
            for i, key_node in enumerate(current.keys):
                key_value = extract_string_value(key_node)
                
                if key_value == step:
                    current = current.values[i]
                    break
            else:
                return None
        elif isinstance(current, ast.List) and isinstance(step, int) and step < len(current.elts):
            current = current.elts[step]
        else:
            return None
    
    return current


# ===== String Extraction =====

def extract_string_value(node: ast.AST) -> Optional[str]:
    """
    Extract string value from various node types.
    
    Args:
        node: The AST node to extract a string from
        
    Returns:
        The extracted string or None if extraction wasn't possible
    """
    # Handle direct string literals
    if isinstance(node, ast.Str):
        return node.s
    # Handle Python 3.8+ Constant nodes
    elif hasattr(ast, 'Constant') and isinstance(node, ast.Constant) and isinstance(getattr(node, 'value', None), str):
        return node.value
    # Handle f-strings
    elif isinstance(node, ast.JoinedStr):
        return extract_fstring(node)
    # Handle string concatenation
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = extract_string_value(node.left)
        right = extract_string_value(node.right)
        
        if left is not None and right is not None:
            return left + right
    
    return None


def extract_fstring(node: ast.JoinedStr) -> str:
    """
    Extract a formatted string representation with placeholders for variables.
    
    Args:
        node: The JoinedStr (f-string) node
        
    Returns:
        String representation with {var} placeholders for formatted values
    """
    parts = []
    for value in node.values:
        if isinstance(value, ast.Str):
            parts.append(value.s)
        elif hasattr(ast, 'Constant') and isinstance(value, ast.Constant):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            if isinstance(value.value, ast.Name):
                parts.append(f"{{{value.value.id}}}")
            else:
                parts.append("{...}")
    return "".join(parts)


def extract_fstring_vars(node: ast.JoinedStr) -> List[str]:
    """
    Extract variable names from a formatted string.
    
    Args:
        node: The JoinedStr (f-string) node
        
    Returns:
        List of variable names used in the f-string
    """
    vars = []
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                vars.append(value.value.id)
    return vars


# ===== Variable Analysis =====

def extract_used_variables(node: ast.AST) -> Set[str]:
    """
    Extract all variable names used in an expression.
    
    Args:
        node: The AST node to analyze
        
    Returns:
        Set of variable names used in the expression
    """
    used_vars = set()
    
    class VariableVisitor(ast.NodeVisitor):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load):
                used_vars.add(node.id)
            self.generic_visit(node)
    
    VariableVisitor().visit(node)
    return used_vars


def variable_name_matches_patterns(var_name: str, patterns: List[str]) -> bool:
    """
    Check if a variable name matches any of the provided patterns.
    
    Args:
        var_name: The variable name to check
        patterns: List of pattern strings to match against
        
    Returns:
        True if the variable name matches any pattern, False otherwise
    """
    var_name_lower = var_name.lower()
    return any(pattern.lower() in var_name_lower for pattern in patterns)


def find_variable_assignments(tree: ast.AST) -> Dict[str, Dict[str, Any]]:
    """
    Find all variable assignments in an AST.
    
    Args:
        tree: The AST to analyze
        
    Returns:
        Dictionary mapping variable names to their assignment info
    """
    variables = {}
    
    class AssignmentVisitor(ast.NodeVisitor):
        def visit_Assign(self, node):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    variables[var_name] = {
                        "node": node.value,
                        "line": node.lineno,
                        "col": node.col_offset,
                        "assign_node": node
                    }
            self.generic_visit(node)
    
    AssignmentVisitor().visit(tree)
    return variables


# ===== Pattern Matching =====

def is_call_matching(node: ast.Call, patterns: List[Dict[str, Any]]) -> bool:
    """
    Check if a function call matches configured patterns.
    
    Args:
        node: The Call node to check
        patterns: List of pattern dictionaries to match against
        
    Returns:
        True if the call matches any pattern, False otherwise
    """
    func_name = get_function_name(node)
    if not func_name:
        return False
        
    for pattern in patterns:
        if pattern.get('type') == 'function' and func_name in pattern.get('names', []):
            return True
        elif pattern.get('type') == 'method_chain':
            attr_chain = get_attribute_chain(node.func)
            for method_pattern in pattern.get('patterns', []):
                object_name = method_pattern.get('object')
                attrs = method_pattern.get('attrs', [])
                
                if len(attr_chain) >= len(attrs) + 1 and attr_chain[0] == object_name:
                    if all(attr in attr_chain[1:] for attr in attrs):
                        return True
    
    return False


def get_nodes_matching_pattern(root: ast.AST, pattern_fn: Callable[[ast.AST], bool]) -> List[ast.AST]:
    """
    Get all nodes that match a specific pattern function.
    
    Args:
        root: The root node to start searching from
        pattern_fn: A function that takes a node and returns True if it matches
        
    Returns:
        List of all nodes that match the pattern
    """
    matching_nodes = []
    
    class PatternVisitor(ast.NodeVisitor):
        def generic_visit(self, node):
            if pattern_fn(node):
                matching_nodes.append(node)
            super().generic_visit(node)
    
    PatternVisitor().visit(root)
    return matching_nodes


# ===== XML Pattern Utils =====

def has_xml_tags(content: str) -> bool:
    """
    Check if a string contains XML-like tags.
    
    Args:
        content: The string to check
        
    Returns:
        True if the string contains XML tags, False otherwise
    """
    return bool(re.search(r'<[^>]+>[^<]*</[^>]+>', content))


def get_xml_tags(content: str) -> List[str]:
    """
    Extract all XML tag names from a string.
    
    Args:
        content: The string to analyze
        
    Returns:
        List of tag names found in the string
    """
    tags = []
    pattern = re.compile(r'<([a-zA-Z0-9_]+)[^>]*>.*?</\1>', re.DOTALL)
    for match in pattern.finditer(content):
        tags.append(match.group(1))
    return tags


def is_var_in_xml_tags(content: str, var_name: str) -> bool:
    """
    Check if a variable is wrapped in XML tags.
    
    Args:
        content: The string content to check
        var_name: The variable name to look for
        
    Returns:
        True if the variable is found within XML tags, False otherwise
    """
    var_pattern = r'\{' + re.escape(var_name) + r'\}'
    xml_patterns = [
        f'<user_input>{var_pattern}</user_input>',
        f'<input>{var_pattern}</input>',
        f'<user>{var_pattern}</user>',
        f'<query>{var_pattern}</query>',
        f'<question>{var_pattern}</question>',
        f'<[^>]+>{var_pattern}</[^>]+>'
    ]
    
    return any(re.search(pattern, content) for pattern in xml_patterns)


# ===== Content Analysis Utilities =====

def find_locations_in_multiline(content: str, 
                               patterns: List[str], 
                               base_line: int = 0,
                               ignore_case: bool = True) -> Dict[str, int]:
    """
    Find line numbers for patterns in multiline content.
    
    Args:
        content: The multiline string content to search
        patterns: List of patterns (strings or regexes) to find in the content
        base_line: The starting line number (used to adjust returned line numbers)
        ignore_case: Whether to ignore case when matching patterns
    
    Returns:
        Dictionary mapping matched patterns to their line numbers
    """
    if not content or not patterns:
        return {}
    
    # If content isn't multiline, simple case
    if "\n" not in content:
        result = {}
        for pattern in patterns:
            if _content_matches_pattern(content, pattern, ignore_case):
                result[pattern] = base_line
        return result
    
    # For multiline content, analyze each line
    lines = content.split("\n")
    results = {}
    
    # Check each line for pattern matches
    for i, line_content in enumerate(lines):
        for pattern in patterns:
            if _content_matches_pattern(line_content, pattern, ignore_case):
                # Record with adjusted line number
                results[pattern] = base_line + i
    
    # For patterns not found line-by-line, check if they span multiple lines
    for pattern in patterns:
        if pattern not in results:
            if _content_matches_pattern(content, pattern, ignore_case):
                # We found it in the full content but not in individual lines,
                # so it might span lines or use different whitespace
                results[pattern] = base_line
    
    return results


def _content_matches_pattern(content: str, pattern: str, ignore_case: bool = True) -> bool:
    """
    Check if content matches a pattern (string or regex).
    
    Args:
        content: The content to check
        pattern: The pattern to find (string or regex)
        ignore_case: Whether to ignore case when matching
    
    Returns:
        True if the pattern is found in the content
    """
    if not content or not pattern:
        return False
        
    # If pattern looks like a regex (has special chars), treat it as such
    if any(c in pattern for c in ".*+?[](){}^$\\|"):
        flags = re.IGNORECASE if ignore_case else 0
        try:
            return bool(re.search(pattern, content, flags))
        except re.error:
            # If regex fails, fall back to simple string matching
            return _simple_string_match(content, pattern, ignore_case)
    else:
        # Simple string matching
        return _simple_string_match(content, pattern, ignore_case)


def _simple_string_match(content: str, pattern: str, ignore_case: bool = True) -> bool:
    """
    Simple string matching for when regex isn't needed.
    
    Args:
        content: The content to check
        pattern: The string pattern to find
        ignore_case: Whether to ignore case
    
    Returns:
        True if the pattern is found in the content
    """
    if ignore_case:
        return pattern.lower() in content.lower()
    return pattern in content


def analyze_term_locations(content: str, 
                          terms: List[str], 
                          base_line: int = 0, 
                          is_regex: bool = False) -> Dict[str, int]:
    """
    Analyze content to find where specific terms appear, with accurate line numbers.
    
    This is particularly useful for rules that need to report issues at specific
    line numbers within multiline string content.
    
    Args:
        content: The content to analyze
        terms: List of terms to find (strings or regex patterns)
        base_line: The base line number of the content
        is_regex: Whether the terms are regex patterns
    
    Returns:
        Dictionary mapping terms to their line numbers
    """
    if not content or not terms:
        return {}
        
    # Convert to list if needed
    if isinstance(terms, str):
        terms = [terms]
    
    debug = os.environ.get('DEBUG') == "1"
    if debug:
        print(f"  - analyze_term_locations: {len(terms)} terms, base_line={base_line}")
        
    # If it's a multiline string with a blank first line (common in Python),
    # we need to handle the line numbering differently
    lines = content.split('\n')
    if lines and lines[0].strip() == "":
        if debug:
            print(f"  - Found empty first line in multiline string")
        # First line is empty, so we need to adjust the content and base line
        adjusted_content = '\n'.join(lines[1:])
        # But keep the original content for the actual searches
        find_content = content
        # Start with line after the empty first line
        adjusted_base = base_line + 1
    else:
        adjusted_content = content
        find_content = content
        adjusted_base = base_line
        
    # If using regex, ensure patterns are properly formed
    if is_regex:
        patterns = []
        for term in terms:
            if debug:
                print(f"  - Processing regex term: {term}")
            try:
                # Don't add word boundaries - the caller should handle this
                # We need the raw patterns for accurate finds
                patterns.append(term)
            except (re.error, TypeError):
                if debug:
                    print(f"  - Error in regex pattern: {term}")
                patterns.append(term)  # Use as-is if error
    else:
        patterns = terms
        
    # Find locations in the content
    results = {}
    for pattern in patterns:
        # For each line in the content
        for i, line_text in enumerate(lines):
            # Calculate the actual line number
            line_num = base_line + i
            
            # Check for matches
            if is_regex:
                try:
                    if re.search(pattern, line_text, re.IGNORECASE):
                        results[pattern] = line_num
                        if debug:
                            print(f"  - Found pattern '{pattern}' at line {line_num}: {line_text}")
                except re.error:
                    # Fall back to simple substring search if regex fails
                    if pattern.lower() in line_text.lower():
                        results[pattern] = line_num
                        if debug:
                            print(f"  - Found pattern (fallback) '{pattern}' at line {line_num}: {line_text}")
            else:
                # Simple substring search
                if pattern.lower() in line_text.lower():
                    results[pattern] = line_num
                    if debug:
                        print(f"  - Found term '{pattern}' at line {line_num}: {line_text}")
    
    if debug:
        print(f"  - Final term locations: {results}")
    return results


def extract_line_from_content(content: str, line_number: int, 
                             context_lines: int = 1) -> str:
    """
    Extract a specific line and surrounding context from multiline content.
    
    Args:
        content: The multiline content
        line_number: The line number to extract (1-indexed relative to content start)
        context_lines: Number of lines of context to include before/after
        
    Returns:
        The extracted line with context, or an empty string if invalid
    """
    if not content or line_number < 1:
        return ""
        
    lines = content.split("\n")
    if line_number > len(lines):
        return ""
        
    # Adjust to 0-indexed
    idx = line_number - 1
    
    # Calculate start and end with context
    start = max(0, idx - context_lines)
    end = min(len(lines), idx + context_lines + 1)
    
    # Extract lines with context
    return "\n".join(lines[start:end])


# ===== Comment Parsing =====

def extract_line_comments(source_code: str) -> Dict[int, str]:
    """
    Extract comments from source code and map them to line numbers.
    
    Args:
        source_code: The source code to extract comments from
        
    Returns:
        Dictionary mapping line numbers to comment text
    """
    comments = {}
    try:
        tokens = tokenize.generate_tokens(StringIO(source_code).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                # Comments start with #, so strip the # character and leading whitespace
                comment_text = token.string.strip()
                line_number = token.start[0]
                comments[line_number] = comment_text
    except tokenize.TokenError:
        # Handle tokenization errors gracefully
        pass
    
    return comments


def parse_exclusion_comments(comments: Dict[int, str]) -> Dict[int, Dict[str, Any]]:
    """
    Parse scanner exclusion comments from the extracted comments.
    
    Recognizes the following patterns:
    - # scanner:ignore - Completely ignore the line for all scanning
    - # scanner:disable=rule-id - Disable specific rule for the line
    - # scanner:disable=rule1,rule2 - Disable multiple rules for the line
    - # scanner:disable - Disable all rules for the line
    
    Args:
        comments: Dictionary mapping line numbers to comment text
        
    Returns:
        Dictionary mapping line numbers to exclusion information
    """
    exclusions = {}
    
    for line_num, comment in comments.items():
        # Check for the ignore pattern
        if "scanner:ignore" in comment:
            exclusions[line_num] = {"type": "ignore", "rules": None}
            
        # Check for the disable pattern
        elif "scanner:disable" in comment:
            # Extract the rules to disable
            match = re.search(r"scanner:disable(?:=([a-zA-Z0-9_,-]+))?", comment)
            if match:
                rule_list = match.group(1)
                if rule_list:
                    # Split by comma for multiple rules
                    rules = [rule.strip() for rule in rule_list.split(",")]
                    exclusions[line_num] = {"type": "disable", "rules": rules}
                else:
                    # No rules specified, disable all
                    exclusions[line_num] = {"type": "disable", "rules": []}
    
    return exclusions