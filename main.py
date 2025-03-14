import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Type
from tqdm import tqdm

from core.analyzer import Analyzer
from scanners.base_scanner import BaseScanner

# Import scanners from their new locations
from scanners.prompt import XMLTagsScanner, SubjectiveTermsScanner, LongListScanner, InefficientCachingScanner
from scanners.chain import UnsafeInputScanner, LangChainScanner
from scanners.output import UnsafeExecutionScanner, StructuredScanner


def get_scanner_categories():
    """Return a dictionary of scanner categories with their subcategories."""
    return {
        "prompt": {
            "description": "Scanners for prompt-related issues",
            "scanners": {
                "xml_tags": {
                    "class": XMLTagsScanner,
                    "description": "Checks for proper XML tag usage in prompts"
                },
                "subjective_terms": {
                    "class": SubjectiveTermsScanner,
                    "description": "Detects subjective terms without clear definitions"
                },
                "long_list": {
                    "class": LongListScanner,
                    "description": "Identifies large data lists in prompts"
                },
                "inefficient_caching": {
                    "class": InefficientCachingScanner, 
                    "description": "Detects inefficient prompt structures for caching",
                    "params": {"min_prompt_length": 200}
                }
            }
        },
        "chain": {
            "description": "Scanners for LLM chain vulnerabilities",
            "scanners": {
                "unsafe_input": {
                    "class": UnsafeInputScanner,
                    "description": "Detects unsanitized user input flowing to LLMs"
                },
                "langchain": {
                    "class": LangChainScanner,
                    "description": "Identifies LangChain-specific vulnerabilities",
                    "params": {"offline_mode": None}  # This will be set from CLI args
                }
            }
        },
        "output": {
            "description": "Scanners for LLM output-related issues",
            "scanners": {
                "unsafe_execution": {
                    "class": UnsafeExecutionScanner,
                    "description": "Detects unsafe execution of LLM outputs"
                },
                "structured": {
                    "class": StructuredScanner,
                    "description": "Validates output models used for parsing LLM responses"
                }
            }
        }
    }


def get_available_scanners() -> Dict[str, dict]:
    """Return a flattened dictionary of all available scanners with their full category paths as keys."""
    categories = get_scanner_categories()
    flattened = {}
    
    for category, category_data in categories.items():
        for scanner_name, scanner_data in category_data["scanners"].items():
            full_name = f"{category}.{scanner_name}"
            flattened[full_name] = scanner_data
    
    return flattened


def list_available_scanners():
    """Print information about all available scanners in a hierarchical format."""
    categories = get_scanner_categories()
    
    print(f"Available scanner categories:")
    for category, category_data in categories.items():
        print(f"\n  {category} - {category_data['description']}")
        
        for scanner_name, scanner_data in category_data["scanners"].items():
            full_name = f"{category}.{scanner_name}"
            print(f"    - {full_name}: {scanner_data['description']}")
            
    print("\nUse --scans with specific scanner IDs (e.g., --scans prompt.xml_tags chain.unsafe_input)")
    print("Or use category names to run all scanners in that category (e.g., --scans prompt chain.unsafe_input)")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="LLM code scanner to detect potential security issues and best practices"
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="Path to file or directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--list_scans", action="store_true", help="List available scanners and exit"
    )
    parser.add_argument(
        "--scans", nargs="+", help="Specific scanners to run (default: all scanners)"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode for more verbose output"
    )
    parser.add_argument(
        "--offline", action="store_true", help="Run in offline mode without fetching remote prompts"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results to a JSON file"
    )
    parser.add_argument(
        "--json-dir", type=str, default="scan_results", 
        help="Directory where JSON reports will be saved (default: scan_results)"
    )
    parser.add_argument(
        "--comprehensive", action="store_true", 
        help="Enable comprehensive logging of all scanned elements, not just issues"
    )
    parser.add_argument(
        "--log-dir", type=str, default="logs", 
        help="Directory where comprehensive logs will be saved (default: logs)"
    )
    return parser.parse_args()


def main():
    print("Starting scanner...")
    args = parse_arguments()
    
    # List available scanners if requested
    if args.list_scans:
        list_available_scanners()
        return
    
    # Enable more verbose output in debug mode
    if args.debug:
        os.environ['DEBUG'] = "1"
        print("Debug mode enabled")
    
    # Initialize the analyzer with scan settings
    analyzer = Analyzer(offline_mode=args.offline)
    
    # Get categories and all available scanners
    categories = get_scanner_categories()
    all_scanners = get_available_scanners()
    
    # Determine which scanners to run
    scanners_to_run = []
    
    if args.scans:
        # Parse requested scanners, handling category and specific scanner names
        for requested in args.scans:
            # If it's a category name (no dot), add all scanners in that category
            if '.' not in requested and requested in categories:
                for scanner_name in categories[requested]["scanners"]:
                    full_name = f"{requested}.{scanner_name}"
                    scanners_to_run.append(full_name)
            # If it's a specific scanner, add it directly
            elif requested in all_scanners:
                scanners_to_run.append(requested)
            # Try partial match against category.scanner pattern
            elif any(name.startswith(requested) for name in all_scanners):
                matches = [name for name in all_scanners if name.startswith(requested)]
                scanners_to_run.extend(matches)
            else:
                print(f"Warning: Unknown scanner '{requested}' - skipping")
    else:
        # If no scanners specified, run all
        scanners_to_run = list(all_scanners.keys())
    
    # Initialize and register the selected scanners
    for full_name in scanners_to_run:
        if full_name not in all_scanners:
            continue
            
        scanner_data = all_scanners[full_name]
        scanner_cls = scanner_data["class"]
        scanner_params = scanner_data.get("params", {})
        
        # Apply runtime parameters
        if "offline_mode" in scanner_params:
            scanner_params["offline_mode"] = args.offline
            
        # Initialize the scanner with parameters
        scanner = scanner_cls(**{k: v for k, v in scanner_params.items() if v is not None})
        
        # Register the scanner
        analyzer.register_scanner(scanner)
        print(f"Registered scanner: {full_name}")
    
    # Get target path
    target_path = Path(args.path)
    issues = []
    
    # Handle both file and directory paths
    files_to_analyze = []
    if target_path.is_file() and target_path.suffix == '.py':
        # If target is a specific Python file, analyze just that file
        files_to_analyze = [target_path]
        print(f"Analyzing single file: {target_path}")
    else:
        # If target is a directory, recursively find all Python files
        files_to_analyze = list(target_path.glob("**/*.py"))
        print(f"Found {len(files_to_analyze)} Python files to analyze")
    
    print("Scanning...")
    for file_path in tqdm(files_to_analyze):
        # Skip the scanner itself to avoid false positives
        if "scanner" in str(file_path) and not file_path.name.endswith("_test.py"):
            continue
        
        if args.debug:
            print(f"\nAnalyzing file: {file_path}")
            # Debug mode - skip extra prompt extraction for now
            pass
            
        file_issues = analyzer.analyze_file(file_path)
        issues.extend(file_issues)
    
    # Report issues
    # Always output to console
    from reporters.console_reporter import ConsoleReporter
    console_reporter = ConsoleReporter()
    console_reporter.report(issues)
    
    # Additionally output to JSON if requested
    if args.json:
        from reporters.json_reporter import JSONReporter
        json_reporter = JSONReporter(output_dir=args.json_dir)
        json_path = json_reporter.report(issues)
        print(f"JSON report saved to: {json_path}")
        
    # Create comprehensive report if requested
    if args.comprehensive:
        from reporters.comprehensive_reporter import ComprehensiveReporter
        comprehensive_reporter = ComprehensiveReporter(output_dir=args.log_dir)
        
        # Collect scanned elements from each scanner
        for scanner in analyzer.scanners:
            if hasattr(scanner, 'scanned_elements') and scanner.scanned_elements:
                for element_type, elements in scanner.scanned_elements.items():
                    for element in elements:
                        comprehensive_reporter.add_scanned_element(element_type, element)
        
        # Generate comprehensive report
        log_path = comprehensive_reporter.report(issues)
        print(f"Comprehensive log saved to: {log_path}")

if __name__ == "__main__":
    main()
