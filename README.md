<div>
  <img src="https://raw.githubusercontent.com/rbitr/kereva-scanner/68b6a59b9a89930b1c8b6aae6f137637cf7de7bd/media/logo.svg" width=50% height=50%><br>
  <a href="https://kereva.io">kereva.io</a> | <a href="mailto:hello@kereva.io">hello@kereva.io</a>
  <hr>
</div>

### This is an early release, please expect bugs and breaking changes

# Kereva LLM Code Scanner

A static analysis tool for scanning Python codebases that use Large Language Models (LLMs) to detect issues that could cause security or performance problems such as hallucination or bias.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan a file or directory
python main.py path/to/file.py
python main.py path/to/directory

# List available scanners
python main.py --list_scans
```

## Key Features

- **Static Analysis**: Analyze code without execution
- **Multiple Scanner Types**: Detect various LLM security & usage issues
- **Comprehensive Reporting**: Console, JSON, and detailed logs

## Basic Usage

```bash
# Scan current directory with all scanners
python main.py

# Run specific scanners
python main.py --scans prompt.subjective_terms chain.unsafe_input

# Run all scanners in a category
python main.py --scans prompt

# Enable debug mode
python main.py --debug

# Run in offline mode (no remote prompt fetching)
python main.py --offline

# Generate JSON report
python main.py --json --json-dir my_reports

# Enable comprehensive logging
python main.py --comprehensive --log-dir custom_logs
```

## Example Scan

Here's an example of scanning a file that incorporates lists into LLM prompts:

```bash
python main.py scandemo/famous.py
```

Sample output:

```
Starting scanner...
Registered scanner: prompt.xml_tags
Registered scanner: prompt.subjective_terms
Registered scanner: prompt.long_list
Registered scanner: prompt.inefficient_caching
Registered scanner: chain.unsafe_input
Registered scanner: chain.langchain
Registered scanner: output.unsafe_execution
Registered scanner: output.structured
Analyzing single file: scandemo/famous.py
Found 10 issues:

Issue #1: prompt-unused-xml-tags (low)
Location: scandemo/famous.py:39
Message: XML tags used in prompt should be explained in the prompt text. Found tags not referenced in text: info
Suggestion: Explain the purpose of XML tags in the prompt text.

Issue #2: prompt-xml-tags (medium)
Location: scandemo/famous.py:21
Message: User input should be enclosed in XML tags for better prompt safety (detected variables: query)
Suggestion: Enclose user input in XML tags, e.g., <user_input>{input_var}</user_input>

Issue #3: prompt-long-list-attention (medium)
Location: scandemo/famous.py:52
Message: Potential attention issues: Long list 'items' is programmatically added to prompt 'messages'. LLMs may struggle with attention over many items.
Suggestion: Consider limiting the number of items, summarizing data, or using a chunking approach.

Issue #4: chain-unsanitized-input (high)
Location: scandemo/famous.py:1
Message: Untrusted input 'question' flows to LLM API call without proper sanitization
Suggestion: Implement input validation or sanitization before passing untrusted input to LLM.

Issue #5: output-structured-unconstrained-field (medium)
Location: scandemo/famous.py:10
Message: Field 'name' in model 'Name' lacks constraints for type 'str'
Suggestion: Add constraints to the field using Field(min_length=1, max_length=100)
```

## Available Scanner Categories

### Prompt Scanners (`prompt`)
- **xml_tags**: XML tag safety in prompts
- **subjective_terms**: Undefined subjective assessments
- **long_list**: Large data list handling
- **inefficient_caching**: Prompt caching efficiency

### Chain Scanners (`chain`)
- **unsafe_input**: Unsanitized user input
- **langchain**: LangChain-specific vulnerabilities

### Output Scanners (`output`)
- **unsafe_execution**: LLM output execution risks
- **structured**: Output model validation

## Run Modes

- **Normal mode**: Full analysis with remote prompt fetching
- **Offline mode** (`--offline`): Skip network requests
- **Comprehensive mode** (`--comprehensive`): Log all scanned elements for audit trails

## Report Formats

- **Console**: Human-readable terminal output
- **JSON**: Structured data for programmatic use
- **Comprehensive logs**: Complete audit trails with all scanned elements

For more detailed documentation on architecture, adding new scanners, or framework support, see the [PROJECT_DOCS.md](PROJECT_DOCS.md) file.
