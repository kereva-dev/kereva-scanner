"""Utility functions for handling Jupyter notebooks."""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


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
            
        # Add a newline if the cell doesn't end with one
        if not source.endswith('\n'):
            source += '\n'
            
        # Track line number mapping
        cell_lines = source.count('\n')
        for i in range(cell_lines):
            line_mapping[synthetic_line_count + i] = cell_num
            
        all_code.append(source)
        synthetic_line_count += cell_lines
    
    combined_code = '\n'.join(all_code)
    return combined_code, line_mapping


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