<div align="center">
  <img src="https://raw.githubusercontent.com/rbitr/kereva-scanner/68b6a59b9a89930b1c8b6aae6f137637cf7de7bd/media/logo.svg" width="300px" alt="Kereva Logo">
  <h1>Kereva LLM Code Scanner</h1>
  <p><strong>Static analysis for LLM-powered Python applications</strong></p>
  <p>
    <a href="https://kereva.io">Website</a> •
    <a href="mailto:hello@kereva.io">Contact</a> •
    <a href="https://discord.gg/E4quCsk7">Join our Discord</a>
  </p>
  </p>
  
  > ⚠️ **Early Release**: Please expect bugs and breaking changes
</div>

<p align="center">
  <img src="https://github.com/kereva-dev/kereva-scanner/blob/master/media/dashboard.gif?raw=true" alt="Scan Example" width="800">
</p>

## 🔍 Overview

Kereva LLM Code Scanner is a static analysis tool designed to identify potential security risks, performance issues, and vulnerabilities in Python codebases that use Large Language Models (LLMs). It analyzes your code without execution to detect problems like hallucination triggers, bias potential, prompt injection vulnerabilities, and inefficient LLM usage patterns.

## ✨ Key Features

- **Static Code Analysis**: Find issues without executing your code
- **Specialized LLM Scanners**: Detect security, quality, and efficiency problems specific to LLM applications
- **Multi-format Support**: Analyze Python files and Jupyter notebooks (.ipynb)
- **Flexible Reporting**: Get results in human-readable console output or structured JSON

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/rbitr/kereva-scanner.git
cd kereva-scanner

# Install dependencies
pip install -r requirements.txt
```

## 📊 Usage

### Basic Scanning

```bash
# Scan a single file
python main.py path/to/file.py

# Scan a Jupyter notebook
python main.py path/to/notebook.ipynb

# Scan an entire directory
python main.py path/to/directory

# Scan the current directory (default)
python main.py
```

### Advanced Options

```bash
# List all available scanners
python main.py --list_scans

# Run specific scanners
python main.py --scans prompt.subjective_terms chain.unsafe_input

# Run all scanners in a category
python main.py --scans prompt

# Generate JSON report
python main.py --json --json-dir reports

# Enable debug mode
python main.py --debug

# Run in offline mode (skip network requests)
python main.py --offline

# Comprehensive logging for audit trails
python main.py --comprehensive --log-dir logs
```
### Excluding Lines from Scanning

You can exclude specific lines from scanning with special comments:

```python
# Completely ignore this line for all scanning
dangerous_input = input("Enter data: ")  # scanner:ignore

# Disable a specific rule for this line
risky_input = input("Enter more: ")  # scanner:disable=chain-unsanitized-input

# Disable multiple rules for this line
multi_excluded = input("Final input: ")  # scanner:disable=chain-unsanitized-input,prompt-subjective-terms

# Disable all rules for this line
exec(response.choices[0].message.content)  # scanner:disable
```

Exclusion comments are useful for:
- Ignoring known issues that can't be fixed yet
- Excluding false positives
- Marking lines that have been reviewed and approved

## 🛡️ Scanner Categories

### Prompt Scanners (`prompt`)

| Scanner | Description |
|---------|-------------|
| `xml_tags` | Detects improper usage of XML tags in prompts |
| `subjective_terms` | Identifies undefined subjective assessments |
| `long_list` | Flags attention issues with large data lists |
| `inefficient_caching` | Locates inefficient prompt caching patterns |
| `system_prompt` | Checks for missing or misplaced system prompts in LLM API calls |

### Chain Scanners (`chain`)
| Scanner | Description |
|---------|-------------|
| `unsafe_input` | Identifies unsanitized user input flowing to LLMs |
| `langchain` | Detects LangChain-specific vulnerabilities |
| `unsafe_output` | Detects vulnerabilities where LLM output is used without proper sanitization in security-sensitive operations |

### Output Scanners (`output`)
| Scanner | Description |
|---------|-------------|
| `unsafe_execution` | Finds potential code execution risks from LLM outputs |
| `structured` | Validates output model definitions and constraints |
| `unsafe_rendering` | Detects when LLM output is used in rendering functions without proper sanitization |
| `safe_shell_commands` | Enforces safe shell command execution with LLM outputs |
| `huggingface_security` | Identifies security vulnerabilities in HuggingFace model usage |

## 📋 Example Output

Running a scan on a sample file with various LLM usage patterns:

```bash
python main.py scandemo/famous.py
```

The scanner produces detailed output highlighting potential issues:

```
Starting scanner...
Registered scanner: prompt.xml_tags
Registered scanner: prompt.subjective_terms
[...]
Found 10 issues:

Issue #1: prompt-unused-xml-tags (low)
Location: scandemo/famous.py:39
Message: XML tags used in prompt should be explained in the prompt text. Found tags not referenced in text: info
Suggestion: Explain the purpose of XML tags in the prompt text.

Issue #2: prompt-xml-tags (medium)
Location: scandemo/famous.py:21
Message: User input should be enclosed in XML tags for better prompt safety (detected variables: query)
Suggestion: Enclose user input in XML tags, e.g., <user_input>{input_var}</user_input>
[...]
```

## 🔧 Run Modes

- **Normal mode**: Full analysis with remote prompt fetching capabilities
- **Offline mode** (`--offline`): Skip network requests for air-gapped environments
- **Comprehensive mode** (`--comprehensive`): Log all scanned elements for complete audit trails

## 📊 Report Formats

- **Console**: Human-readable terminal output with clear issue categorization and suggestions
- **JSON**: Structured data format for programmatic analysis and integration with other tools
- **Comprehensive log**s: Complete audit trails with detailed information about all scanned elements

## 💼 Use Cases

- **Security Audits**: Identify potential vulnerabilities before deployment
- **Quality Assurance**: Find common LLM usage patterns that lead to poor results
- **Developer Education**: Learn best practices for prompt engineering and LLM application design
- **CI/CD Integration**: Automate LLM security checks in your deployment pipeline

## 📖 Documentation

For more detailed documentation on:
- Architecture and design
- Adding custom scanners
- Framework-specific support

See the [PROJECT_DOCS.md](PROJECT_DOCS.md) file.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## 📧 Contact

For questions, feedback, or support, please contact us at [hello@kereva.io](mailto:hello@kereva.io) or visit [kereva.io](https://kereva.io).

---

<div align="center">
  <p>Made with ❤️ by <a href="https://kereva.io">Kereva</a></p>
</div>
