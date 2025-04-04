"""Rule for enforcing safe shell command execution with LLM outputs.

This rule checks if LLM outputs are being passed to shell functions with commands and arguments
that are on a pre-defined allowlist. Commands or arguments not on the allowlist will be flagged.
"""

import ast
import os
from typing import Any, Optional, Dict, List, Set, Tuple
from rules.base_rule import BaseRule
from core.issue import Issue
from core.ast_utils import get_function_name, get_attribute_chain
from core.config import SHELL_EXECUTION_FUNCTIONS, SAFE_SHELL_COMMANDS

class SafeShellCommandsRule(BaseRule):
    """Rule to enforce only safe shell commands are used with LLM outputs."""
    
    def __init__(self):
        super().__init__(
            rule_id="output-safe-shell-commands",
            description="LLM output is passed to shell commands not on the safe list",
            severity="high",
            tags=["security", "shell-injection", "command-execution"]
        )
        
    def check(self, node_info: Any, context: Optional[dict] = None) -> Optional[Issue]:
        """Check if LLM output is passed to shell functions with unsafe commands."""
        context = context or {}
        
        debug = os.environ.get('DEBUG') == "1"
        if debug:
            print(f"SafeShellCommandsRule checking node: {type(node_info).__name__}")
            if "llm_output_vars" in context:
                print(f"Context has {len(context.get('llm_output_vars', []))} LLM output vars")
            
            # Show all tainted vars detected by the scanner
            if context.get("tainted_vars"):
                print(f"Detected tainted variables: {context.get('tainted_vars')}")
            
        # This rule expects an AST call node or a dictionary of LLM output variables
        if isinstance(node_info, ast.Call):
            node = node_info
            # We need to check both the explicit LLM output vars AND any tainted vars detected by the scanner
            llm_output_vars = context.get("llm_output_vars", set())
            tainted_vars = context.get("tainted_vars", set())
            
            # Combine them for simplicity
            all_suspicious_vars = llm_output_vars.union(tainted_vars)
            
            if debug:
                print(f"All suspicious variables: {all_suspicious_vars}")
            
            # Check if this is a call to a shell execution function
            func_name = self._get_full_function_name(node)
            
            if debug:
                print(f"Checking function call: {func_name} at line {getattr(node, 'lineno', 'unknown')}")
                if any(shell_func in func_name for shell_func in SHELL_EXECUTION_FUNCTIONS):
                    print(f"This is a shell execution function")
            
            if any(shell_func in func_name for shell_func in SHELL_EXECUTION_FUNCTIONS):
                # CRITICAL SECURITY CHECK: Direct LLM output to shell function
                # This is the most dangerous case - directly executing arbitrary LLM-generated commands
                # Example: os.system(llm_command) - This must always be flagged
                if len(node.args) > 0 and isinstance(node.args[0], ast.Name):
                    var_name = node.args[0].id
                    
                    # Check against both explicit LLM vars and tainted vars
                    if var_name in all_suspicious_vars:
                        if debug:
                            print(f"CRITICAL SECURITY ISSUE: Direct tainted output '{var_name}' passed to {func_name}")
                        return self._create_issue(
                            node, var_name, func_name, 0,
                            f"Direct LLM output used as shell command - arbitrary command execution vulnerability",
                            context
                        )
                
                # ALWAYS CHECK FOR COMMON UNSAFE SHELL COMMANDS IN STRINGS
                # Check whether this is a string with ls -a, rm, find, etc. - dangerous commands 
                if len(node.args) > 0 and isinstance(node.args[0], ast.JoinedStr):
                    cmd_str = ""
                    for value in node.args[0].values:
                        if isinstance(value, ast.Constant):
                            cmd_str += value.value
                    
                    # Look for specific dangerous patterns in command strings
                    if "rm -rf" in cmd_str or "rm -r" in cmd_str:
                        return self._create_issue(
                            node, "f-string", func_name, 0,
                            f"Dangerous 'rm -rf' or 'rm -r' command with LLM output - could cause data loss",
                            context
                        )
                    
                    if cmd_str.startswith("rm ") or " rm " in cmd_str:
                        return self._create_issue(
                            node, "f-string", func_name, 0,
                            f"Unsafe 'rm' command with LLM output - remove command is not on the safe list",
                            context
                        )
                        
                    if cmd_str.startswith("find ") or " find " in cmd_str:
                        return self._create_issue(
                            node, "f-string", func_name, 0,
                            f"Unsafe 'find' command with LLM output - find command is not on the safe list",
                            context
                        )
                        
                    if "ls -a" in cmd_str:
                        return self._create_issue(
                            node, "f-string", func_name, 0,
                            f"Unsafe 'ls -a' command with LLM output - the -a flag is not on the safe list",
                            context
                        )
                    
                # Check each argument for potential LLM output
                has_llm_output = False
                llm_var_name = None
                arg_position = None
                
                # Check regular arguments
                for i, arg in enumerate(node.args):
                    # Direct variable reference (should have been caught above for arg 0, but check again)
                    if isinstance(arg, ast.Name) and arg.id in llm_output_vars:
                        has_llm_output = True
                        llm_var_name = arg.id
                        arg_position = i
                        if debug:
                            print(f"Found direct LLM output variable '{arg.id}' at position {i}")
                    
                    # Check for f-string with LLM variables
                    elif isinstance(arg, ast.JoinedStr):
                        for j, value in enumerate(arg.values):
                            if isinstance(value, ast.FormattedValue):
                                if isinstance(value.value, ast.Name) and value.value.id in all_suspicious_vars:
                                    has_llm_output = True
                                    llm_var_name = value.value.id
                                    arg_position = i
                                    
                                    # Check for unsafe command patterns in the f-string
                                    # Extract the command from the f-string literal parts
                                    cmd_str = ""
                                    for literal_part in arg.values:
                                        if isinstance(literal_part, ast.Constant):
                                            cmd_str += literal_part.value
                                    
                                    if debug:
                                        print(f"Found LLM output '{value.value.id}' in f-string: '{cmd_str}' at position {i}")
                                    
                                    # Look for specific command patterns
                                    if "ls -a" in cmd_str or cmd_str.startswith("ls -a"):
                                        return self._create_issue(
                                            node, llm_var_name, func_name, i,
                                            f"Unsafe command 'ls -a' with LLM output - 'ls -a' is not on the safe commands list",
                                            context
                                        )
                                    
                                    if "find" in cmd_str and cmd_str.startswith("find"):
                                        return self._create_issue(
                                            node, llm_var_name, func_name, i,
                                            f"Unsafe command 'find' with LLM output - 'find' is not on the safe commands list",
                                            context
                                        )
                                        
                                    if "rm" in cmd_str and cmd_str.startswith("rm"):
                                        return self._create_issue(
                                            node, llm_var_name, func_name, i,
                                            f"Unsafe command 'rm' with LLM output - 'rm' is not on the safe commands list",
                                            context
                                        )
                
                # Check keyword arguments too
                for kw in node.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id in llm_output_vars:
                        has_llm_output = True
                        llm_var_name = kw.value.id
                        if debug:
                            print(f"Found LLM output '{kw.value.id}' in keyword argument '{kw.arg}'")
                        # Special handling for command-related keywords
                        if kw.arg in ['command', 'cmd', 'args', 'shell_command']:
                            return self._create_issue(node, kw.value.id, func_name, kw_arg=kw.arg, 
                                                    message="LLM output passed as shell command", 
                                                    context=context)
                
                # If we found LLM output in any of the arguments
                if has_llm_output:
                    # Extract command information
                    command_info = self._extract_command_info(node, arg_position, context)
                    
                    if debug:
                        if command_info:
                            print(f"Extracted command info: {command_info}")
                        else:
                            print(f"Could not extract command info")
                    
                    if not command_info:
                        # If we can't determine the command, flag it
                        return self._create_issue(node, llm_var_name, func_name, arg_position, 
                                                "Cannot determine shell command", context)
                    
                    # Check if command is on the safe list
                    command, arguments = command_info
                    
                    if command not in SAFE_SHELL_COMMANDS:
                        return self._create_issue(node, llm_var_name, func_name, arg_position, 
                                                f"Command '{command}' is not on the safe list", 
                                                context)
                    
                    # Check if all arguments are allowed
                    allowed_args = SAFE_SHELL_COMMANDS[command]
                    
                    # If '*' in allowed_args, all arguments are allowed
                    if '*' not in allowed_args:
                        for arg in arguments:
                            if arg not in allowed_args:
                                return self._create_issue(node, llm_var_name, func_name, arg_position, 
                                                        f"Argument '{arg}' for command '{command}' is not on the safe list", 
                                                        context)
        
        return None
    
    def _extract_command_info(self, node: ast.Call, arg_pos: int, 
                              context: Dict) -> Optional[Tuple[str, List[str]]]:
        """
        Extract command and arguments from the node.
        Returns a tuple of (command, [arg1, arg2, ...]) or None if extraction fails.
        """
        debug = os.environ.get('DEBUG') == "1"
        func_name = self._get_full_function_name(node)
        
        if debug:
            print(f"Extracting command info for {func_name} at position {arg_pos}")
            if node.args and arg_pos < len(node.args):
                print(f"Argument type: {type(node.args[arg_pos]).__name__}")
        
        # RULE 1: Direct LLM variable to shell function
        # For direct passing of LLM output to os.system or similar functions
        # Example: os.system(llm_command)
        if arg_pos == 0 and any(func in func_name for func in ["os.system", "os.popen"]):
            # If this is a direct LLM variable like os.system(llm_command)
            if isinstance(node.args[0], ast.Name):
                # We can't determine the command, so treat it as unsafe
                if debug:
                    print(f"Direct LLM output to {func_name} - UNSAFE: unknown command")
                return "unknown_command", []
        
        # RULE 2: List-style subprocess with known command but LLM args
        # For subprocess.run(["cmd", "arg1", "arg2", llm_path], ...)
        if arg_pos > 0 and isinstance(node.args[0], ast.List):
            # Command is passed as a list of arguments
            elements = node.args[0].elts
            if elements and isinstance(elements[0], ast.Constant) and isinstance(elements[0].value, str):
                command = elements[0].value
                if debug:
                    print(f"List-style command: {command} with LLM arg at position {arg_pos}")
                return command, []  # We don't care about the args here, just checking if command is safe
        
        # RULE 3: f-string with shell command
        # For f-string commands like f"ls -a {llm_path}" or f"rm {file_path}"
        if isinstance(node.args[arg_pos], ast.JoinedStr):
            # Extract the literal parts of the f-string
            parts = []
            for value in node.args[arg_pos].values:
                if isinstance(value, ast.Constant):
                    parts.append(value.value)
            
            # If we have at least one literal part, try to extract the command
            if parts:
                cmd_str = "".join(parts).strip()
                if debug:
                    print(f"Extracted f-string literal parts: '{cmd_str}'")
                
                # Look for common command patterns - be more flexible in matching
                if cmd_str.startswith("ls") or " ls " in cmd_str:
                    if "-a" in cmd_str:
                        if debug:
                            print(f"Found ls -a command (UNSAFE)")
                        return "ls", ["-a"]
                    if "-l" in cmd_str:
                        if debug:
                            print(f"Found ls -l command (SAFE)")
                        return "ls", ["-l"]
                    # Default to ls with no args
                    return "ls", []
                elif cmd_str.startswith("rm ") or " rm " in cmd_str:
                    if debug:
                        print(f"Found rm command (UNSAFE)")
                    return "rm", []
                elif cmd_str.startswith("find ") or " find " in cmd_str:
                    if debug:
                        print(f"Found find command (UNSAFE)")
                    return "find", []
                elif cmd_str.startswith("cat ") or " cat " in cmd_str:
                    if debug:
                        print(f"Found cat command (SAFE)")
                    return "cat", []
                
                # Try to extract the first word as the command
                parts = cmd_str.split()
                if parts:
                    command = parts[0]
                    if debug:
                        print(f"Extracted command from first word: {command}")
                    return command, parts[1:] if len(parts) > 1 else []
        
        # RULE 4: Find any remaining commands with shell=True
        has_shell = False
        for kw in node.keywords:
            if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                has_shell = True
                break
        
        if has_shell and arg_pos == 0:
            # With shell=True, the first argument could be a string or an f-string
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                command_str = node.args[0].value.strip()
                parts = command_str.split()
                if parts:
                    if debug:
                        print(f"Extracted command from shell=True constant: {parts[0]}")
                    return parts[0], parts[1:] if len(parts) > 1 else []
            
            # For f-strings with shell=True (already handled above, but keep for completeness)
            elif isinstance(node.args[0], ast.JoinedStr):
                # This case should have been caught by RULE 3 above
                pass
        
        # RULE 5: ALWAYS FAIL SAFE - If we reach here, we couldn't determine the command safely
        # We should fail safe and return a command that will trigger a rule violation
        if debug:
            print(f"Could not determine command safely, treating as unknown (UNSAFE)")
        return "unknown_command", []
    
    def _create_issue(self, node: ast.Call, var_name: str, func_name: str, 
                      arg_pos: Optional[int] = None, message: str = "", 
                      context: Dict = None, kw_arg: Optional[str] = None) -> Issue:
        """Create an issue from the given information."""
        context = context or {}
        
        # Get source code context and code snippet if available
        source_code = context.get("code", "")
        code_snippet = None
        
        if source_code and hasattr(node, 'lineno'):
            # Get up to 3 lines of context around the line of code
            lines = source_code.split('\n')
            start_line = max(0, node.lineno - 2)
            end_line = min(len(lines), node.lineno + 1)
            code_snippet = '\n'.join(lines[start_line:end_line])
        
        # Create more detailed context information
        issue_context = {
            "variable": var_name, 
            "function": func_name,
            "code_snippet": code_snippet
        }
        
        if arg_pos is not None:
            issue_context["arg_position"] = arg_pos
        
        if kw_arg:
            issue_context["keyword_arg"] = kw_arg
            
        # If we have variable definition information, include it
        var_defs = context.get("variable_definitions", {})
        if var_name in var_defs:
            issue_context["variable_definition"] = {
                "line": var_defs[var_name].get("line", 0),
                "source": var_defs[var_name].get("source", "unknown")
            }
            
        # Build the issue message
        if not message:
            if kw_arg:
                message = f"LLM output variable '{var_name}' is passed to shell function '{func_name}' as keyword argument '{kw_arg}'"
            else:
                message = f"LLM output variable '{var_name}' is passed to shell function '{func_name}' at position {arg_pos}"
        else:
            if kw_arg:
                message = f"{message} - LLM output variable '{var_name}' is passed to shell function '{func_name}' as keyword argument '{kw_arg}'"
            else:
                message = f"{message} - LLM output variable '{var_name}' is passed to shell function '{func_name}'"
        
        return Issue(
            rule_id=self.rule_id,
            message=message,
            location=self._get_location(node),
            severity=self.severity,
            tags=self.tags,
            fix_suggestion="Only use shell commands from the approved safe list with appropriate arguments. Configure the allowlist in core/config.py",
            context=issue_context
        )
    
    def _get_full_function_name(self, node: ast.Call) -> str:
        """Get the full function name including module/class path."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return ".".join(get_attribute_chain(node.func))
        return ""
    
    def _get_location(self, node: ast.AST) -> Dict[str, Any]:
        """Get the location information for a node."""
        return {
            "line": getattr(node, "lineno", 0),
            "col": getattr(node, "col_offset", 0),
            "end_line": getattr(node, "end_lineno", 0),
            "end_col": getattr(node, "end_col_offset", 0)
        }