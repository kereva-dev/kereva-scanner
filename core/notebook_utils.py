"""Utility functions for handling Jupyter notebooks."""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set


def extract_code_from_notebook(notebook_path: Path) -> Tuple[str, Dict[int, int]]:
    """
    Extract Python code from a Jupyter notebook.
    
    Args:
        notebook_path: Path to the notebook file
        
    Returns:
        Tuple containing:
        - A string with all code cells concatenated
        - A mapping of synthetic line numbers to original cell numbers for error reporting
    """
    with open(notebook_path, 'r', encoding='utf-8') as f:
        notebook = json.load(f)
    
    code_cells = [cell for cell in notebook.get('cells', []) 
                 if cell.get('cell_type') == 'code']
    
    all_code = []
    line_mapping = {}
    synthetic_line_count = 1
    
    for cell_num, cell in enumerate(code_cells):
        source = cell.get('source', [])
        if isinstance(source, list):
            source = ''.join(source)
        
        # Skip empty cells
        if not source.strip():
            continue
            
        # Process the cell content to handle triple quotes and magic commands
        processed_source = process_cell_content(source)
        
        # Add a newline if the cell doesn't end with one
        if not processed_source.endswith('\n'):
            processed_source += '\n'
            
        # Track line number mapping
        cell_lines = processed_source.count('\n')
        for i in range(cell_lines):
            line_mapping[synthetic_line_count + i] = cell_num
            
        all_code.append(processed_source)
        synthetic_line_count += cell_lines
    
    combined_code = '\n'.join(all_code)
    return combined_code, line_mapping


def process_cell_content(source: str) -> str:
    """
    Process a notebook cell's source code to handle special cases.
    
    This properly handles multi-line constructs while correctly 
    identifying IPython magic commands:
    - Recognizes triple quoted strings (triple single and double quotes)
    - Handles escaped quotes in string literals
    - Ignores % and ! characters in comments
    - Recognizes IPython magic commands only outside string literals
    - Handles backslash continuations for magic commands
    
    Args:
        source: The source code from a notebook cell
        
    Returns:
        Processed source with magic commands replaced by pass statements
    """
    lines = source.split('\n')
    processed_lines = []
    
    in_triple_double_quotes = False
    in_triple_single_quotes = False
    in_magic_command = False
    
    i = 0
    while i < len(lines):
        line = lines[i]
        processed_line = line  # Default to keeping the line
        
        # If we're inside a triple-quoted string, simply add the line as is
        if in_triple_double_quotes or in_triple_single_quotes:
            # Count unescaped triple quotes to check if we're exiting the string
            def count_unescaped_triple_quotes(text, quote_type):
                pattern = r'(?<!\\)' + quote_type * 3
                return len(re.findall(pattern, text))
            
            triple_double_count = count_unescaped_triple_quotes(line, '"')
            triple_single_count = count_unescaped_triple_quotes(line, "'")
            
            # Check if we're exiting a triple-quoted string
            if in_triple_double_quotes and triple_double_count % 2 == 1:
                in_triple_double_quotes = False
            if in_triple_single_quotes and triple_single_count % 2 == 1:
                in_triple_single_quotes = False
                
            processed_lines.append(processed_line)
            i += 1
            continue
        
        # Handle comments - anything after # that's not in a string
        code_part = line
        comment_part = ""
        if "#" in line:
            parts = line.split("#", 1)
            code_part = parts[0]
            comment_part = "#" + parts[1] if len(parts) > 1 else ""
        
        # Check for triple quotes to see if we're entering a string
        def count_unescaped_triple_quotes(text, quote_type):
            pattern = r'(?<!\\)' + quote_type * 3
            return len(re.findall(pattern, text))
        
        triple_double_count = count_unescaped_triple_quotes(code_part, '"')
        triple_single_count = count_unescaped_triple_quotes(code_part, "'")
        
        # Check if we're entering a triple-quoted string
        if triple_double_count % 2 == 1:
            in_triple_double_quotes = True
        if triple_single_count % 2 == 1:
            in_triple_single_quotes = True
            
        # Only process as magic commands if we're not inside a string literal
        if not in_triple_double_quotes and not in_triple_single_quotes:
            stripped = code_part.strip()
            
            # Check for magic commands - but only if we're not in a string context
            if (stripped.startswith('!') or stripped.startswith('%') or 
                stripped.startswith('%%')) and not in_magic_command:
                in_magic_command = True
                processed_line = 'pass  # IPython magic command removed' + comment_part
            elif in_magic_command:
                # Check if line ends with backslash for continuation
                if stripped.endswith('\\'):
                    processed_line = 'pass  # IPython magic command continuation' + comment_part
                else:
                    in_magic_command = False
                    processed_line = 'pass  # IPython magic command end' + comment_part
        
        processed_lines.append(processed_line)
        i += 1
    
    return '\n'.join(processed_lines)


def get_original_cell_number(synthetic_line: int, line_mapping: Dict[int, int]) -> int:
    """
    Map a synthetic line number to the original cell number.
    
    Args:
        synthetic_line: The line number in the combined code
        line_mapping: Mapping from synthetic lines to cell numbers
        
    Returns:
        The original cell number
    """
    # Find the nearest line number in the mapping that's less than or equal to synthetic_line
    valid_lines = [l for l in line_mapping.keys() if l <= synthetic_line]
    if not valid_lines:
        return 0
    
    nearest_line = max(valid_lines)
    return line_mapping[nearest_line]