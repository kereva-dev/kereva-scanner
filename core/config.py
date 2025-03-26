"""
Configuration Module

This module contains shared configuration and pattern definitions used by multiple scanners and rules.
Centralizing these patterns makes it easier to maintain and update them.
"""

# Vulnerability Types
VULNERABILITY_TYPES = {
    "UNTRUSTED_TO_LLM": "untrusted_to_llm",
    "SYSTEM_ARGV_TO_LLM": "system_argv_to_llm",
    "LLM_STRAIGHT_PATH": "llm_straight_path",
    "LLM_TO_UNSAFE_OUTPUT": "llm_to_unsafe_output",
    "UNSAFE_COMPLETE_CHAIN": "unsafe_complete_chain"  # Full chain from untrusted input through LLM to unsafe output
}

# Patterns for identifying LLM API calls across different providers
LLM_API_PATTERNS = [
    {
        'type': 'function',
        'names': [
            'generate', 'generate_text', 'generate_content', 'complete', 'completion',
            'pipeline', 'text_generator', 'generator'  # HuggingFace-specific function names
        ]
    },
    {
        'type': 'method_chain',
        'patterns': [
            # OpenAI
            {'object': 'openai', 'attrs': ['Completion', 'create']},
            {'object': 'openai', 'attrs': ['ChatCompletion', 'create']},
            {'object': 'client', 'attrs': ['chat', 'completions', 'create']},
            {'object': 'client', 'attrs': ['completions', 'create']},
            {'object': 'openai_client', 'attrs': ['chat', 'completions', 'create']},
            {'object': 'openai_client', 'attrs': ['completions', 'create']},
            
            # Anthropic
            {'object': 'anthropic', 'attrs': ['messages', 'create']},
            {'object': 'anthropic', 'attrs': ['completions', 'create']},
            {'object': 'client', 'attrs': ['messages', 'create']},
            
            # HuggingFace
            {'object': 'pipeline', 'attrs': ['__call__']},
            {'object': 'model', 'attrs': ['generate']},
            {'object': 'AutoModelForCausalLM', 'attrs': ['from_pretrained']},
            {'object': 'AutoModelForCausalLM', 'attrs': ['generate']},
            {'object': 'AutoModelForSeq2SeqLM', 'attrs': ['generate']},
            {'object': 'TextGenerationPipeline', 'attrs': ['__call__']},
            {'object': 'generator', 'attrs': ['generate']},
            {'object': 'HfInferenceEndpoint', 'attrs': ['text_generation']},
            {'object': 'InferenceClient', 'attrs': ['text_generation']},
            {'object': 'endpoint', 'attrs': ['text_generation']},
            {'object': 'client', 'attrs': ['text_generation']},
            
            # LangChain
            {'object': 'llm', 'attrs': ['predict']},
            {'object': 'llm', 'attrs': ['invoke']},
            {'object': 'chain', 'attrs': ['invoke']},
            {'object': 'chain', 'attrs': ['run']}
        ]
    }
]

# Patterns for identifying LangChain-specific calls
LANGCHAIN_PATTERNS = [
    {
        'type': 'function',
        'names': [
            'load_prompt', 'from_template'
        ]
    },
    {
        'type': 'method_chain',
        'patterns': [
            {'object': 'hub', 'attrs': ['pull']},
            {'object': 'ChatPromptTemplate', 'attrs': ['from_template']},
            {'object': 'PromptTemplate', 'attrs': ['from_template']},
            {'object': 'ChatPromptTemplate', 'attrs': ['from_messages']}
        ]
    }
]

# Variable names that suggest untrusted external input
UNTRUSTED_INPUT_PATTERNS = [
    "user_input", "query", "question", "prompt", "request", 
    "user_message", "input", "user_query", "message", "text",
    "customer_request", "client_input", "human_input",
    "argv"  # Add support for command line arguments
]

# Variable names that suggest a prompt
PROMPT_VARIABLE_PATTERNS = [
    "prompt", "template", "system_message", "sys_message",
    "human_message", "user_message", "ai_message", "assistant_message",
    "lookup", "extract", "query", "message"
]

# Common XML tags used in prompts
COMMON_XML_TAGS = [
    "user_input", "input", "user", "query", "question", "context",
    "system", "human", "ai", "assistant", "example", "document"
]

# Common sanitization function names
SANITIZATION_FUNCTION_PATTERNS = [
    'sanitize', 'clean', 'escape', 'validate', 'filter',
    'html.escape', 'bleach.clean', 'strip_tags'
]

# Common function names for LLM API calls
LLM_FUNCTION_NAMES = [
    'chat', 'generate', 'complete', 'create_completion', 
    'generate_text', 'ask_llm', 'query_llm'
]

# Common method chain patterns for LLM API calls
LLM_METHOD_CHAIN_PATTERNS = [
    {'obj': 'openai', 'methods': ['create', 'generate', 'complete']},
    {'obj': 'client', 'methods': ['create', 'chat', 'complete']},
    {'obj': 'anthropic', 'methods': ['create', 'complete', 'messages']}
]

# LLM API keyword arguments that might contain untrusted input
LLM_UNTRUSTED_PARAM_NAMES = [
    'messages', 'prompt', 'content', 'input'
]

# Patterns for identifying potential output sinks
OUTPUT_SINK_PATTERNS = [
    # Common variable names used for output
    'result', 'output', 'response', 'answer', 'completion', 
    'generated_text', 'llm_output', 'llm_response', 'chat_response',
    'assistant_response', 'ai_response', 'prediction',
    
    # Function names that might be used for output handling
    'print', 'execute', 'eval', 'exec', 'system', 'popen', 'subprocess',
    'write', 'save', 'log', 'display', 'render', 'return', 'json.dumps'
]

# Operations that suggest unsafe output usage
UNSAFE_OUTPUT_OPERATIONS = [
    'exec', 'eval', 'subprocess.run', 'subprocess.Popen', 'os.system',
    'run_command', 'execute_command', 'execute_script', 'execute_code',
    'compile', '__import__', 'importlib.import_module'
]

# Patterns for detecting output sanitization functions
OUTPUT_SANITIZATION_FUNCTIONS = [
    'validate_output', 'sanitize_output', 'clean_output', 'escape_output',
    'encode', 'json.loads', 'parse', 'schema.validate', 'model.parse',
    'check_output', 'filter_output', 'process_output', 'verify_output'
]