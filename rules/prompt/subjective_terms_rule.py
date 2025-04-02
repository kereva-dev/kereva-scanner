import re
from typing import Optional, Dict, Any, List
from rules.base_rule import BaseRule
from core.issue import Issue


class SubjectiveTermsRule(BaseRule):
    """Rule to check if prompts contain subjective terms that can lead to unreliable or biased output.
    
    Subjective terms like 'best', 'worst', 'most important', etc. can lead to
    unreliable or biased LLM output when not properly defined in context.
    """
    
    def __init__(self):
        super().__init__(
            rule_id="prompt-subjective-terms",
            description="Prompts should avoid subjective terms without clear definitions",
            severity="medium"
        )
        self.suggestion = "Define what 'best', 'most important', etc. mean in context or use more specific criteria"
        
        # List of subjective terms to check for
        self.subjective_terms = [
            r"\bbest\b", 
            r"\bworst\b", 
            r"\bmost important\b",
            r"\bkey\b", 
            r"\bessential\b",
            r"\bcritical\b",
            r"\bsignificant\b",
            r"\bmain\b", 
            r"\bprimary\b",
            r"\bvital\b",
            r"\boptimal\b",
            r"\bhighest quality\b",
            r"\bbetter\b",
            r"\bworse\b",
            r"\bgreater\b",
            r"\blesser\b",
            r"\bgood\b",
            r"\bexcellent\b",
            r"\bgreat\b",
            r"\bawesome\b",
            r"\bterrific\b"
        ]
        
        # Patterns that indicate the term is defined or constrained
        self.definition_patterns = [
            r"by (\w+ ){0,3}I mean",
            r"defined as",
            r"according to",
            r"based on (\w+ ){0,5}criteria",
            r"measured by",
            r"in terms of",
            r"with respect to",
            r"meaning"
        ]
    
    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> Optional[Issue]:
        """Check prompt content for subjective terms without clear definitions."""
        # For prompt-based rules, node is a dict with prompt information
        if 'content' not in node:
            return None
        
        content = node.get('content', '')
        line = node.get('line', 0)
        
        # Skip if content is not a string
        if not isinstance(content, str):
            return None
        
        # Extract template variables if they exist
        template_variables = node.get('template_variables', [])
        
        # Create a masked version of content to exclude template variables from analysis
        masked_content = content
        
        # If this is a template (f-string or format string), mask variables
        if node.get('is_template', False) and template_variables:
            # Mask f-string variables like {variable_name}
            for var in template_variables:
                # Skip empty variable names
                if not var:
                    continue
                # Create pattern that captures variable name including any format specifiers
                pattern = r'\{' + re.escape(var) + r'(?:\:[^\}]*)?\}'
                # Replace with a placeholder that won't match subjective terms
                masked_content = re.sub(pattern, f"__VAR_{var}__", masked_content)
        
        # Also mask other formatting placeholders like {0}, {1}, {} etc.
        masked_content = re.sub(r'\{\d+(?:\:[^\}]*)?\}', '__VAR_POS__', masked_content)
        masked_content = re.sub(r'\{(?:\:[^\}]*)?\}', '__VAR_FMT__', masked_content)
            
        # Check for subjective terms in the masked content
        found_terms = []
        term_locations = {}
        is_multiline = "\n" in content
        lines = content.split("\n") if is_multiline else [content]
        
        # First, find terms in each line and record their line numbers
        for i, line_content in enumerate(lines):
            for term_pattern in self.subjective_terms:
                matches = re.finditer(term_pattern, line_content, re.IGNORECASE)
                for match in matches:
                    if match and match.group(0) not in found_terms:
                        # Make sure it's not part of our variable placeholder
                        if '__VAR_' not in match.group(0):
                            term = match.group(0)
                            found_terms.append(term)
                            # Record the line where this term appears
                            actual_line = line + i  # Base line number + offset in multiline content
                            term_locations[term] = actual_line
                            
        # Check entire content for terms that might span multiple lines
        if not found_terms:
            for term_pattern in self.subjective_terms:
                matches = re.finditer(term_pattern, masked_content, re.IGNORECASE)
                for match in matches:
                    if match and match.group(0) not in found_terms:
                        # Make sure it's not part of our variable placeholder
                        if '__VAR_' not in match.group(0):
                            term = match.group(0)
                            found_terms.append(term)
                            # We couldn't find the line by line search, so use base line
                            if term not in term_locations:
                                term_locations[term] = line
        
        # If no subjective terms found, no issue
        if not found_terms:
            return None
            
        # Check if definitions are provided for the terms
        has_definition = any(re.search(pattern, content, re.IGNORECASE) for pattern in self.definition_patterns)
        
        # If definitions are provided, no issue
        if has_definition:
            return None
            
        # Use the line number of the first term in multiline content
        # This gives a more accurate location of where the issue occurs
        reported_line = line
        if found_terms and term_locations:
            first_term = found_terms[0]
            if first_term in term_locations:
                reported_line = term_locations[first_term]
        
        # Create issue for subjective terms without definitions
        issue_message = f"Found subjective terms ({', '.join(found_terms)}) without clear definitions"
        
        # Add location information for better debugging
        term_info = []
        for term in found_terms:
            if term in term_locations:
                term_info.append(f"{term} (line {term_locations[term]})")
            else:
                term_info.append(term)
                
        if term_info:
            issue_message += f"\nTerm locations: {', '.join(term_info)}"
        
        # Get the code snippet context from the identified location
        if is_multiline and reported_line > line:
            # Calculate the offset in the content
            offset = reported_line - line
            if offset < len(lines):
                code_snippet = lines[offset-1:offset+2]  # Get a few lines around the term
                code_snippet = "\n".join(code_snippet)
            else:
                code_snippet = content[:50] + "..." if len(content) > 50 else content
        else:
            code_snippet = content[:50] + "..." if len(content) > 50 else content
        
        return Issue(
            rule_id=self.rule_id,
            message=issue_message,
            location={"line": reported_line, "file": context.get("file_name", "unknown")},
            severity=self.severity,
            fix_suggestion=self.suggestion,
            context={
                "code_snippet": code_snippet,
                "term_locations": term_locations
            }
        )