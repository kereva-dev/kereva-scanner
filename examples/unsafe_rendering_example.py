"""
Example showing vulnerable code patterns where LLM output is rendered unsafely.
This demonstrates several patterns that could lead to XSS vulnerabilities.
"""

import openai
from anthropic import Anthropic
import markdown
import bleach
import html
from bs4 import BeautifulSoup

# For web framework examples
try:
    from flask import Flask, render_template, render_template_string
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
except ImportError:
    # Mock Flask and FastAPI for example purposes
    class Flask:
        def __init__(self, name):
            self.name = name
    
    def render_template(template, **kwargs):
        return f"Rendering {template} with {kwargs}"
    
    def render_template_string(template, **kwargs):
        return f"Rendering string template with {kwargs}"
    
    class HTMLResponse:
        def __init__(self, content):
            self.content = content
    
    class FastAPI:
        def __init__(self):
            pass

# Configure API clients
openai.api_key = "dummy-api-key"
anthropic = Anthropic(api_key="dummy-api-key")

def get_markdown_from_llm():
    """Get markdown content from an LLM."""
    response = openai.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Write me a markdown document about Python programming."}
        ]
    )
    # Extract markdown from response
    llm_markdown = response.choices[0].message.content
    return llm_markdown

def get_html_from_llm():
    """Get HTML content from an LLM."""
    response = anthropic.completions.create(
        prompt="\n\nHuman: Generate an HTML snippet for a contact form\n\nAssistant:",
        max_tokens_to_sample=300,
        model="claude-2"
    )
    # Extract HTML from response
    llm_html = response.completion.strip()
    return llm_html

def unsafe_markdown_rendering():
    """Vulnerable example using markdown rendering with LLM output."""
    response = openai.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Write me a markdown document about Python programming."}
        ]
    )
    
    # Extract markdown content - make this very clear for the scanner
    llm_output = response.choices[0].message.content
    md_content = llm_output
    
    # VULNERABLE: Directly rendering LLM-generated markdown
    print("Rendering LLM-generated markdown:")
    html_content = markdown.markdown(md_content)  # This is potentially dangerous!
    
    # Display the HTML
    print(html_content)

def unsafe_html_rendering():
    """Vulnerable example using direct HTML from LLM."""
    response = anthropic.completions.create(
        prompt="\n\nHuman: Generate an HTML snippet for a contact form\n\nAssistant:",
        max_tokens_to_sample=300,
        model="claude-2"
    )
    
    # Extract HTML directly from LLM response
    llm_output = response.completion.strip()
    html_content = llm_output
    
    # VULNERABLE: Directly using LLM-generated HTML
    print("Using LLM-generated HTML directly:")
    
    # Simulate a web app response with unescaped HTML
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return render_template_string(html_content)  # This is dangerous!
    
    # Or with FastAPI
    fast_app = FastAPI()
    
    @fast_app.get("/")
    def read_root():
        return HTMLResponse(content=html_content)  # This is dangerous!
    
    # Or parsing with BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')
    print(soup.prettify())

def safe_markdown_rendering():
    """Safe example using markdown rendering with sanitization."""
    md_content = get_markdown_from_llm()
    
    # SAFE: Sanitize the markdown output after rendering
    print("Safely rendering LLM-generated markdown:")
    
    # First convert to HTML
    html_content = markdown.markdown(md_content)
    
    # Then sanitize the HTML output
    sanitized_html = bleach.clean(
        html_content,
        tags=['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'ul', 'ol', 'li', 'strong', 'em', 'code'],
        attributes={'a': ['href']},
        strip=True
    )
    
    print(sanitized_html)

def safe_html_rendering():
    """Safe example using HTML from LLM with sanitization."""
    html_content = get_html_from_llm()
    
    # SAFE: Sanitize the HTML before using it
    sanitized_html = bleach.clean(
        html_content,
        tags=['form', 'input', 'label', 'button', 'div', 'p', 'h1', 'h2', 'h3', 'span'],
        attributes={
            'form': ['action', 'method'],
            'input': ['type', 'name', 'placeholder'],
            'button': ['type']
        },
        strip=True
    )
    
    # Now it's safe to use in a web app
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return render_template_string(sanitized_html)  # Safe because we sanitized
    
    # Or with FastAPI
    fast_app = FastAPI()
    
    @fast_app.get("/")
    def read_root():
        return HTMLResponse(content=sanitized_html)  # Safe because we sanitized

def alternative_safe_approach():
    """Alternative approach: escape HTML entities."""
    html_content = get_html_from_llm()
    
    # SAFE: Escape HTML entities before displaying
    escaped_html = html.escape(html_content)
    
    # Now it's safe to display as text
    print(f"<pre>{escaped_html}</pre>")
    
    # This would show the HTML code rather than rendering it
    # Useful for code examples or debugging

def main():
    print("Running examples of unsafe and safe LLM output rendering...")
    
    # Unsafe examples
    unsafe_markdown_rendering()
    unsafe_html_rendering()
    
    # Safe examples
    safe_markdown_rendering()
    safe_html_rendering()
    alternative_safe_approach()

if __name__ == "__main__":
    main()