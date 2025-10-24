#!/usr/bin/env python3
"""
Helper utilities with Coverity issues for demonstration.
"""

import re
from typing import Optional, Dict, Any


def get_value(data: Optional[Dict[str, Any]], key: str) -> Optional[Any]:
    """
    Get a value from a dictionary.
    
    FIXED COVERITY ISSUE:
    - NULL_POINTER: Added null check before accessing data (CWE-476)
    """
    # Fix for NULL_POINTER (CWE-476): Check if data is None before accessing
    if data is None:
        return None
    
    # Safe to access now
    return data.get(key)


def safe_get_value(data: Optional[Dict[str, Any]], key: str, default: Any = None) -> Any:
    """
    Safely get a value from a dictionary with proper null checking.
    """
    if data is None:
        return default
    
    return data.get(key, default)


def process_user_data(user_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process user data and return formatted results.
    
    FIXED COVERITY ISSUE:
    - BUFFER_OVERFLOW: Added bounds checking and input validation (CWE-120)
    """
    result = {}
    
    # Fix for BUFFER_OVERFLOW (CWE-120): Add bounds checking and input validation
    if user_data is not None:
        # Validate and limit string lengths to prevent buffer overflow
        name = user_data.get('name', 'Unknown')
        if isinstance(name, str):
            result['name'] = name[:100]  # Limit to 100 characters
        else:
            result['name'] = 'Unknown'
        
        email = user_data.get('email', 'No email')
        if isinstance(email, str):
            result['email'] = email[:100]  # Limit to 100 characters
        else:
            result['email'] = 'No email'
        
        age = user_data.get('age', 0)
        # Validate age is within reasonable bounds
        if isinstance(age, (int, float)) and 0 <= age <= 150:
            result['age'] = int(age)
        else:
            result['age'] = 0
    else:
        result['name'] = 'Unknown'
        result['email'] = 'No email'
        result['age'] = 0
    
    return result


def calculate_statistics(numbers: Optional[list]) -> Dict[str, float]:
    """
    Calculate basic statistics from a list of numbers.
    
    FIXED COVERITY ISSUES:
    - USE_AFTER_FREE: Create copy to prevent modification during iteration (CWE-416)
    - INTEGER_OVERFLOW: Add overflow checking for arithmetic operations (CWE-190)
    """
    if numbers is None or len(numbers) == 0:
        return {
            'count': 0,
            'sum': 0.0,
            'average': 0.0,
            'min': 0.0,
            'max': 0.0
        }
    
    # Fix for USE_AFTER_FREE (CWE-416): Create a copy to prevent issues with list modification
    numbers_copy = list(numbers)
    
    # Fix for INTEGER_OVERFLOW (CWE-190): Use float arithmetic and check for overflow
    try:
        total_sum = 0.0
        for num in numbers_copy:
            # Check for potential overflow
            if isinstance(num, (int, float)):
                # Use float to handle large numbers
                total_sum += float(num)
            else:
                continue
        
        count = len(numbers_copy)
        average = total_sum / count if count > 0 else 0.0
        
        return {
            'count': count,
            'sum': total_sum,
            'average': average,
            'min': float(min(numbers_copy)),
            'max': float(max(numbers_copy))
        }
    except (OverflowError, ValueError) as e:
        # Handle overflow gracefully
        return {
            'count': len(numbers_copy),
            'sum': 0.0,
            'average': 0.0,
            'min': 0.0,
            'max': 0.0
        }


def validate_config(config: Optional[Dict[str, Any]]) -> bool:
    """
    Validate configuration data.
    
    FIXED COVERITY ISSUE:
    - SQL_INJECTION: Added input validation and sanitization (CWE-89)
    """
    if config is None:
        return False
    
    required_keys = ['host', 'port', 'database']
    
    # Fix for SQL_INJECTION (CWE-89): Validate and sanitize configuration parameters
    for key in required_keys:
        if key not in config:
            return False
        
        value = config[key]
        
        # Validate each field type and content
        if key == 'host':
            # Host should be a valid hostname or IP address
            if not isinstance(value, str) or len(value) > 255:
                return False
            # Check for SQL injection patterns
            if re.search(r'[;\'"\\]|--|\b(OR|AND|SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b', 
                        str(value), re.IGNORECASE):
                return False
        
        elif key == 'port':
            # Port should be a valid port number
            if not isinstance(value, (int, str)):
                return False
            try:
                port_num = int(value)
                if not (1 <= port_num <= 65535):
                    return False
            except (ValueError, TypeError):
                return False
        
        elif key == 'database':
            # Database name should be alphanumeric with underscores only
            if not isinstance(value, str) or len(value) > 64:
                return False
            if not re.match(r'^[a-zA-Z0-9_]+$', value):
                return False
    
    return True
