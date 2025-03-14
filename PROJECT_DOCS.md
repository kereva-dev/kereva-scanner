# LLM Code Scanner - Detailed Documentation

This document contains in-depth information about the LLM Code Scanner architecture, how to add new scanners, and other technical details.

## Detailed Scanner Descriptions

### Prompt Scanners (`prompt`)

#### prompt.xml_tags
Analyzes prompt templates and detects issues with XML tag usage for better prompt safety.

**Rules:**
- **XMLTagRule**: Checks for proper XML tag usage in prompts
- **UnusedXMLTagsRule**: Checks if XML tags are explained in the prompt

#### prompt.subjective_terms
Detects subjective terms in prompts that can lead to unreliable or biased LLM outputs when not properly defined.

**Detection Capability:**
Detects terms like:
- Comparative terms: "best", "worst", "better", "worse"
- Importance terms: "key", "essential", "critical"
- Priority terms: "main", "primary", "vital"

#### prompt.long_list
Detects code that adds long lists of data points to prompts, which may exceed LLM attention limits.

#### prompt.inefficient_caching
Detects inefficient prompt structures that could impact caching and performance.

### Chain Scanners (`chain`)

#### chain.unsafe_input
Performs taint analysis to detect unsanitized user input flowing to LLMs.

#### chain.langchain
Analyzes LangChain code to detect framework-specific issues such as RAG vulnerabilities, unsafe input handling, and missing XML tags in templates.

**Features:**
- Automatically fetches prompt templates from LangChain Hub
- Detects unsafe user input flowing through LangChain components
- Identifies LangChain-specific vulnerabilities

### Output Scanners (`output`)

#### output.unsafe_execution
Detects unsafe usage of LLM outputs where results could lead to code execution or command injection vulnerabilities.

**Detection Capability:**
The scanner detects LLM outputs flowing to dangerous functions:
- Python code execution: `eval()`, `exec()`
- OS command execution: `os.system()`, `subprocess.run()`

#### output.structured
Analyzes Pydantic models used for structured output parsing to prevent LLM hallucination.

**Rules:**
- **UnconstrainedFieldRule**: Detects fields without proper constraints
- **MissingDefaultRule**: Ensures fields have default values

## Architecture

The scanner follows a modular architecture that separates concerns and allows for extensibility:

```
scanner/
├── core/                    # Core functionality
│   ├── analyzer.py          # Orchestrates the scanning process
│   ├── ast_utils.py         # Common AST utility functions
│   ├── base_visitor.py      # Base AST visitor with common functionality
│   ├── config.py            # Shared configuration and patterns
│   ├── issue.py             # Issue data structure
│   └── prompt_fetcher.py    # Fetches remote prompts from sources
├── rules/                   # Rule definitions
│   ├── base_rule.py         # Base class for rules
│   ├── chain/               # Rules for chain vulnerabilities
│   ├── output/              # Rules for output-related issues
│   │   └── structured/      # Rules for structured output validation
│   └── prompt/              # Rules for prompt-related issues
│       └── xml_tags/        # Rules for XML tag handling
├── scanners/                # Scanner implementations
│   ├── base_scanner.py      # Base class for scanners
│   ├── chain/               # Chain vulnerability scanners
│   ├── output/              # Output-related scanners
│   └── prompt/              # Prompt-related scanners
├── reporters/               # Output formatting
│   ├── console_reporter.py  # Terminal output
│   ├── json_reporter.py     # JSON file output
│   └── comprehensive_reporter.py # Complete audit trails
└── main.py                  # Command-line interface
```

## Adding New Scanners

The scanner framework is designed to be easily extensible. Follow these steps to add a new scanner:

### 1. Decide the scanner category

Determine if your scanner fits into one of the existing categories:
- **prompt**: For scanners related to LLM prompt content issues
- **chain**: For scanners related to LLM chain vulnerabilities 
- **output**: For scanners related to LLM output handling

### 2. Create a new scanner class

Create a new file in the appropriate category directory (e.g., `scanners/prompt/my_scanner.py`):

```python
from scanners.base_scanner import BaseScanner
from core.issue import Issue
from core.ast_utils import get_function_name, is_call_matching
from core.base_visitor import BaseVisitor
from core.config import LLM_API_PATTERNS
import ast

class MyScanner(BaseScanner):
    """Description of what the scanner does."""
    
    def __init__(self):
        # Initialize with appropriate rules (create your own or use existing ones)
        rules = []
        super().__init__(rules)
    
    def scan(self, ast_node, context=None):
        """
        Scan the code for specific issues.
        
        Args:
            ast_node: The parsed AST tree
            context: Dictionary with scanning context (file name, code, etc.)
            
        Returns:
            List of Issue objects
        """
        context = context or {}
        
        # Create a visitor that inherits from the base visitor
        visitor = MyVisitor(context)
        visitor.visit(ast_node)
        
        # Collect issues found by the visitor
        self.issues.extend(visitor.issues)
        
        return self.issues


class MyVisitor(BaseVisitor):
    """Custom visitor for this scanner that inherits common functionality."""
    
    def __init__(self, context):
        super().__init__(context)
        self.issues = []
    
    def visit_Call(self, node):
        # Example: detect specific function calls using shared utilities
        if is_call_matching(node, LLM_API_PATTERNS):
            # Found an LLM API call, check for issues
            self.issues.append(Issue(
                rule_id='category-my-rule-id',  # Use category prefix in rule ID
                severity='medium',
                message='Issue detected in LLM API call',
                location={
                    'line': node.lineno,
                    'column': node.col_offset,
                    'file': self.context.get('file_name', '<unknown>')
                }
            ))
        
        # Continue the traversal
        super().visit_Call(node)
```

### 3. Implement your scanning logic

There are two main approaches to scanning:

#### a. AST-based scanning with the BaseVisitor

Use the BaseVisitor class to inherit common functionality:

```python
from core.base_visitor import BaseVisitor
from core.ast_utils import extract_string_value, variable_name_matches_patterns
from core.config import UNTRUSTED_INPUT_PATTERNS

class MyVisitor(BaseVisitor):
    def __init__(self, context):
        super().__init__(context)
        self.issues = []
        
    def visit_Call(self, node):
        # Use pre-built state tracking
        func_name = self.get_function_name(node)
        if func_name == 'vulnerable_function':
            # Access tracked variables
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    var_name = arg.id
                    # Use shared pattern matching
                    if variable_name_matches_patterns(var_name, UNTRUSTED_INPUT_PATTERNS):
                        self.issues.append(Issue(
                            rule_id='category-my-rule-id',
                            severity='medium',
                            message=f'Untrusted input {var_name} used in vulnerable function',
                            location={
                                'line': node.lineno,
                                'column': node.col_offset,
                                'file': self.context.get('file_name', '<unknown>')
                            }
                        ))
        
        # Continue traversal
        super().visit_Call(node)
```

#### b. Content-based scanning

Use regex or string operations to analyze code content:

```python
import re
from core.issue import Issue

# In your scanner's scan method:
code = context.get('code', '')
file_name = context.get('file_name', '<unknown>')

pattern = r'dangerous_pattern\((.+?)\)'
for match in re.finditer(pattern, code):
    # Calculate line number from the match position
    line_number = code[:match.start()].count('\n') + 1
    
    self.issues.append(Issue(
        rule_id='category-my-rule-id',
        severity='high',
        message='Dangerous pattern detected',
        suggestion='Use safe_pattern() instead',
        location={
            'line': line_number,
            'file': file_name
        }
    ))
```

### 4. Create rules for your scanner (optional)

For more complex scanners, create rule classes in the appropriate category directory:

```python
# rules/category/my_rule.py
from rules.base_rule import BaseRule

class MyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id='category-my-rule-id',  # Use category prefix for rule IDs
            description='Description of the issue',
            severity='medium'
        )
        self.suggestion = 'How to fix the issue'
    
    def check(self, node, context=None):
        # Rule-specific logic to check if the issue exists
        # Return an Issue object if the issue is found, None otherwise
        return None
```

### 5. Update __init__.py for imports

Ensure that your scanner and rules are importable by updating the __init__.py files:

```python
# scanners/category/__init__.py
from scanners.category.my_scanner import MyScanner

# rules/category/__init__.py
from rules.category.my_rule import MyRule
```

### 6. Register your scanner

Add your scanner to the scanner categories in `main.py`:

```python
def get_scanner_categories():
    """Return a dictionary of scanner categories with their subcategories."""
    return {
        "prompt": {
            "description": "Scanners for prompt-related issues",
            "scanners": {
                # ... existing scanners ...
                "my_scanner": {
                    "class": MyScanner,
                    "description": "Description of what my scanner does"
                }
            }
        },
        # ... other categories ...
    }
```

### 7. Import your scanner in main.py

Add the import at the top of `main.py` in the appropriate section:

```python
# Import scanners from their new locations
from scanners.prompt import XMLTagsScanner, SubjectiveTermsScanner, MyScanner  # Add your scanner here
from scanners.chain import UnsafeInputScanner, LangChainScanner
from scanners.output import UnsafeExecutionScanner, StructuredScanner
```

## Supporting New Frameworks

The scanner architecture makes it easy to add support for new LLM frameworks. Here's how to add support for a new framework:

1. **Identify Framework-Specific Patterns**:
   - Understand how the framework constructs and sends prompts to LLMs
   - Identify common security patterns and anti-patterns
   - Document the framework's API conventions

2. **Extend Existing Scanners**:
   - Add framework-specific API patterns to `core/config.py` in the `LLM_API_PATTERNS` section
   - Update the shared configuration with framework-specific patterns

3. **Create a Framework-Specific Scanner**:
   - Create a new scanner class that inherits from `BaseScanner`
   - Implement framework-specific analysis logic in the `scan` method
   - Define rules for common security issues in the framework

4. **Register the New Scanner**:
   - Add the scanner to `get_available_scanners()` in `main.py`
   - Document the scanner's capabilities and rules

## Core Concepts

### Issues

Issues are the output of the scanning process, representing problems found in the code:

```python
Issue(
    rule_id='rule-id',           # Unique identifier for the rule
    severity='high',             # high, medium, or low
    message='Issue description',  
    suggestion='How to fix it',   
    context={},                  # Additional context for the issue
    location={
        'line': 42,              # Line number where the issue was found
        'column': 10,            # Column number
        'file': 'file_name.py'   # File name
    }
)
```

### Scanners

Scanners are responsible for analyzing code and detecting issues:

- `BaseScanner`: Abstract base class for all scanners
- Each scanner implements the `scan` method to detect specific issues
- Scanners may use AST parsing, regex matching, or other techniques

### Rules

Rules define what issues to look for:

- `BaseRule`: Abstract base class for all rules
- Each rule implements the `check` method to detect a specific issue
- Rules are typically used by scanners to identify specific patterns