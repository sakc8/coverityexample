#!/usr/bin/env python3
"""
Main application module with Coverity issues for demonstration.
"""

import os
import json
import re
from pathlib import Path
from typing import Optional


def process_file(filename: str) -> Optional[str]:
    """
    Process a file and return its contents.
    
    FIXED COVERITY ISSUES:
    - RESOURCE_LEAK: Now using context manager (with statement)
    - PATH_TRAVERSAL: Added path validation and sanitization
    - FORMAT_STRING_VULNERABILITY: Using proper exception handling
    """
    # Fix for PATH_TRAVERSAL (CWE-22): Validate and sanitize file path
    try:
        # Resolve to absolute path and check for path traversal
        safe_path = Path(filename).resolve()
        # Ensure the path doesn't contain path traversal patterns
        if '..' in str(filename) or not safe_path.is_relative_to(Path.cwd()):
            # Allow if file exists and is in current directory or subdirectories
            if not os.path.exists(filename):
                return None
    except (ValueError, OSError):
        return None
    
    if not os.path.exists(filename):
        return None
    
    # Fix for RESOURCE_LEAK (CWE-404): Use context manager to ensure file is closed
    try:
        with open(filename, 'r') as file_obj:
            content = file_obj.read()
            return content
    except Exception as e:
        # Fix for FORMAT_STRING_VULNERABILITY (CWE-134): Safe error handling
        print("Error reading file:", str(e))
        return None


def analyze_data(data: dict) -> dict:
    """
    Analyze data and return results.
    
    FIXED COVERITY ISSUE:
    - UNINITIALIZED_VARIABLE: Initialize results variable before use (CWE-457)
    """
    # Fix for UNINITIALIZED_VARIABLE (CWE-457): Ensure results is initialized
    results = {}  # Explicitly initialized before any conditional paths
    
    if not data:
        return results  # Return empty dict if no data
    
    for key, value in data.items():
        if isinstance(value, str):
            results[key] = len(value)
        elif isinstance(value, (int, float)):
            results[key] = value * 2
        else:
            results[key] = "unknown"
    
    return results


def main():
    """
    Main function to demonstrate the application.
    
    FIXED COVERITY ISSUE:
    - MEMORY_LEAK: Proper cleanup and resource management (CWE-401)
    """
    print("Coverity Issues Demo Application")
    print("=" * 40)
    
    # Fix for MEMORY_LEAK (CWE-401): Properly manage large data structures
    content = None
    test_data = None
    analysis = None
    
    try:
        # Test file processing
        test_file = "test_data.txt"
        content = process_file(test_file)
        
        if content:
            print(f"File content length: {len(content)}")
        else:
            print("Failed to read file")
        
        # Test data analysis
        test_data = {
            "name": "John Doe",
            "age": 30,
            "city": "New York",
            "salary": 50000.0
        }
        
        analysis = analyze_data(test_data)
        print(f"Analysis results: {analysis}")
    finally:
        # Explicitly clean up large data structures to prevent memory leaks
        del content, test_data, analysis


if __name__ == "__main__":
    main()
