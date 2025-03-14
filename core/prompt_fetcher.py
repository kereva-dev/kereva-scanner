import re
import importlib.util
from typing import Optional, Dict, Any, List, Tuple
import ast

class PromptFetcher:
    """
    Utility class for fetching prompt templates from remote sources like LangChain Hub.
    Uses the actual LangChain hub.pull function when available.
    """
    
    def __init__(self, offline_mode=False):
        self.offline_mode = offline_mode
        self.cache = {}  # Cache fetched prompts to avoid duplicate requests
        self._langchain_available = None  # Lazy-check if LangChain is available
    
    def fetch_langchain_hub_prompt(self, prompt_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a prompt template from LangChain Hub using the actual hub.pull function.
        
        Args:
            prompt_id: The ID of the prompt in the format "owner/name"
            
        Returns:
            Dictionary with prompt information or None if fetching fails
        """
        if self.offline_mode:
            print(f"  - Running in offline mode, skipping fetch for prompt: {prompt_id}")
            return None
        
        if prompt_id in self.cache:
            return self.cache[prompt_id]
        
        try:
            print(f"  - Fetching LangChain hub prompt: {prompt_id}")
            
            # Check if LangChain is available
            if not self._is_langchain_available():
                print(f"  - LangChain not installed. Can't fetch prompt: {prompt_id}")
                print(f"  - To enable fetching, install langchain: pip install langchain langchain-hub")
                return None
            
            # Import LangChain modules at runtime only when needed
            from langchain import hub
            
            # Fetch the prompt template using the actual hub.pull function
            prompt_template = hub.pull(prompt_id)
            if not prompt_template:
                print(f"  - Failed to retrieve prompt: {prompt_id}")
                return None
                
            # Extract template content and variables
            if hasattr(prompt_template, "template"):
                template = prompt_template.template
            elif hasattr(prompt_template, "messages"):
                # Handle chat templates
                template = str(prompt_template.messages)
            else:
                # Fall back to string representation
                template = str(prompt_template)
            
            variables = self.extract_template_variables(template)
            
            result = {
                "id": prompt_id,
                "content": template,
                "variables": variables,
                "source": "langchain_hub"
            }
            
            # Cache the result
            self.cache[prompt_id] = result
            return result
            
        except Exception as e:
            print(f"  - Error fetching prompt {prompt_id}: {str(e)}")
            return None
    
    def _is_langchain_available(self) -> bool:
        """Check if LangChain is installed."""
        if self._langchain_available is not None:
            return self._langchain_available
            
        # Check for langchain installation
        has_langchain = importlib.util.find_spec("langchain") is not None
        
        # Check for hub module in modern LangChain (part of langchain package)
        # or older langchain_hub package
        has_hub = False
        if has_langchain:
            try:
                # Try to import hub from langchain
                import langchain
                has_hub = hasattr(langchain, 'hub')
            except ImportError:
                # Check for separate langchain_hub package for older versions
                has_hub = importlib.util.find_spec("langchain_hub") is not None
        
        self._langchain_available = has_langchain and has_hub
        return self._langchain_available
        
    def extract_template_variables(self, template: str) -> List[str]:
        """
        Extract variable names from a template string.
        
        Args:
            template: Template string with {variable} placeholders
            
        Returns:
            List of variable names
        """
        if not template:
            return []
            
        # Look for {variable} pattern
        variables = re.findall(r'\{([^{}]+)\}', template)
        return list(set(variables))  # Remove duplicates
        
    def has_xml_tags(self, template: str) -> bool:
        """
        Check if a template uses XML tags.
        
        Args:
            template: Template string to check
            
        Returns:
            True if XML tags are found, False otherwise
        """
        if not template:
            return False
            
        # Basic check for <tag>...</tag> pattern
        xml_pattern = re.compile(r'<([a-zA-Z0-9_-]+)>.*?</\1>')
        return bool(xml_pattern.search(template))
        
    def extract_prompt_id_from_node(self, node: ast.AST) -> Optional[str]:
        """
        Extract prompt ID from an AST node representing a hub.pull() call.
        
        Args:
            node: AST node for the hub.pull() call
            
        Returns:
            Prompt ID string or None if not found
        """
        if not isinstance(node, ast.Call):
            return None
            
        # Check if it's hub.pull()
        if not (isinstance(node.func, ast.Attribute) and 
                node.func.attr == "pull" and 
                isinstance(node.func.value, ast.Name) and 
                node.func.value.id == "hub"):
            return None
            
        # Extract the prompt ID argument
        if len(node.args) > 0:
            if isinstance(node.args[0], ast.Str):
                return node.args[0].s
            elif hasattr(ast, 'Constant') and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return node.args[0].value
                
        return None