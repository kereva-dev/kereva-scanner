"""
Configuration Module

This module contains shared configuration and pattern definitions used by multiple scanners and rules.
Centralizing these patterns makes it easier to maintain and update them.
"""

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
