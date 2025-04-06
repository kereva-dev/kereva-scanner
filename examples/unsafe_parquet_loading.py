"""
Example of vulnerable Parquet file loading patterns that could be affected by CVE-2025-30065

This file demonstrates code patterns that load Parquet files from potentially untrusted sources
without proper validation, which could lead to remote code execution vulnerabilities.
"""

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from fastparquet import ParquetFile
import requests
from io import BytesIO
import os
from typing import Dict, Any


def load_user_uploaded_parquet(file_path: str) -> pd.DataFrame:
    """
    Load a Parquet file directly from a user-provided path
    VULNERABLE: No validation of source or content
    """
    return pd.read_parquet(file_path)


def load_from_url(url: str) -> pd.DataFrame:
    """
    Download and load a Parquet file from a URL
    VULNERABLE: No validation of source or content
    """
    response = requests.get(url)
    return pd.read_parquet(BytesIO(response.content))


def process_external_dataset(source_path: str) -> Dict[str, Any]:
    """
    Process an external dataset from a Parquet file
    VULNERABLE: Using PyArrow without validation
    """
    table = pq.read_table(source_path)
    return {
        "num_rows": table.num_rows,
        "schema": str(table.schema),
        "data": table.to_pandas().to_dict()
    }


def load_user_file_with_fastparquet(file_path: str) -> Dict[str, Any]:
    """
    Load a user-provided Parquet file using fastparquet
    VULNERABLE: No validation of the file source or content
    """
    pf = ParquetFile(file_path)
    df = pf.to_pandas()
    return {
        "columns": list(df.columns),
        "data": df.to_dict()
    }


class LLMDataProcessor:
    """Example class that loads Parquet files for an LLM application"""
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        
    def load_rag_embeddings(self, user_requested_file: str) -> pd.DataFrame:
        """
        Load RAG embeddings from a user-requested Parquet file
        VULNERABLE: No validation of user input in file path
        """
        file_path = os.path.join(self.data_dir, user_requested_file)
        if not file_path.endswith('.parquet'):
            file_path += '.parquet'
        
        # Vulnerable: No validation of the file before loading
        embeddings_df = pd.read_parquet(file_path)
        return embeddings_df


# SAFER ALTERNATIVES (still recommended to implement additional validation)

def safer_load_with_validation(file_path: str) -> pd.DataFrame:
    """
    A safer approach with basic validation
    NOTE: This is still not completely safe - additional measures are recommended
    """
    # Basic validation of file path
    if not os.path.exists(file_path) or not file_path.endswith('.parquet'):
        raise ValueError(f"Invalid Parquet file path: {file_path}")
    
    # Check file size before loading (avoid loading extremely large files)
    file_size = os.path.getsize(file_path)
    if file_size > 100 * 1024 * 1024:  # 100 MB limit
        raise ValueError(f"File too large: {file_size} bytes")
    
    # Could add additional checks here:
    # - Verify file checksums against a known good value
    # - Scan file with antivirus
    # - Run in a sandboxed environment
    
    # Load the file with version check
    # NOTE: This doesn't actually prevent the vulnerability, just checks the version
    import pyarrow
    if pyarrow.__version__ < '1.15.1':
        print("WARNING: Using a vulnerable version of PyArrow. Update to 1.15.1+")
    
    # Load with read_parquet
    return pd.read_parquet(file_path)


if __name__ == "__main__":
    # Examples of vulnerable usage
    # DO NOT run this with untrusted files!
    
    # Direct loading from user input (simulated)
    user_file = input("Enter parquet file path: ")  # VULNERABLE
    df = load_user_uploaded_parquet(user_file)
    
    # Using in a RAG context (simulated)
    processor = LLMDataProcessor("./data")
    user_embedding_file = input("Which embedding set? ")  # VULNERABLE
    embeddings = processor.load_rag_embeddings(user_embedding_file)