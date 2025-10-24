"""
FastMCP Server for Coverity Issue Management
Provides tools to analyze and fix Coverity static analysis issues
"""

from fastmcp import FastMCP
import json
import os
from pathlib import Path
from typing import List, Dict, Any

# Initialize FastMCP server
mcp = FastMCP("Coverity Issue Fixer")

def read_file_content(file_path: str, project_root: str = None) -> str:
    """Read file content from the project directory"""
    if project_root is None:
        project_root = os.getcwd()
    
    full_path = os.path.join(project_root, file_path)
    
    if not os.path.exists(full_path):
        return f"Error: File {file_path} not found"
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

def get_file_context(file_path: str, line_number: int, context_lines: int = 5, project_root: str = None) -> Dict[str, Any]:
    """Get file context around the issue line"""
    if project_root is None:
        project_root = os.getcwd()
    
    full_path = os.path.join(project_root, file_path)
    
    if not os.path.exists(full_path):
        return {"error": f"File {file_path} not found"}
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        context = {
            "file_path": file_path,
            "target_line": line_number,
            "start_line": start_line + 1,
            "end_line": end_line,
            "context": "".join(lines[start_line:end_line]),
            "issue_line": lines[line_number - 1].strip() if line_number <= len(lines) else "",
            "total_lines": len(lines)
        }
        
        return context
    except Exception as e:
        return {"error": f"Error reading file: {str(e)}"}

@mcp.tool()
def fix_coverity_issues(coverity_json_path: str = "coverity_issues.json") -> str:
    """
    Analyze Coverity issues from JSON file and provide detailed information for fixing.
    
    **USE THIS TOOL WHEN**: User asks to "fix coverity issues", "fix coverity", "resolve coverity issues",
    or any similar request about Coverity static analysis issues.
    
    This tool:
    1. Parses the Coverity issues JSON file
    2. Identifies which files and lines have issues
    3. Provides context around each issue
    4. Returns recommendations for fixing each issue
    5. AI should then fix ONLY the specific issues listed in the JSON at the exact lines mentioned
    
    Args:
        coverity_json_path: Path to the Coverity issues JSON file (default: coverity_issues.json)
    
    Returns:
        Detailed analysis of all Coverity issues with file context and fix recommendations.
        The AI should read this output and then fix ONLY those specific issues mentioned.
    """
    try:
        # Determine project root
        project_root = os.getcwd()
        
        # Read Coverity issues JSON
        json_full_path = os.path.join(project_root, coverity_json_path)
        
        if not os.path.exists(json_full_path):
            return f"Error: Coverity issues file not found at {coverity_json_path}"
        
        with open(json_full_path, 'r', encoding='utf-8') as f:
            coverity_data = json.load(f)
        
        issues = coverity_data.get('issues', [])
        
        if not issues:
            return "No Coverity issues found in the JSON file."
        
        # Build detailed response
        response = []
        response.append("=" * 80)
        response.append("COVERITY ISSUES ANALYSIS")
        response.append("=" * 80)
        response.append("")
        
        # Summary
        summary = coverity_data.get('summary', {})
        response.append(f"Total Issues: {summary.get('total_issues', len(issues))}")
        response.append(f"High Severity: {summary.get('high_severity', 0)}")
        response.append(f"Medium Severity: {summary.get('medium_severity', 0)}")
        response.append(f"Low Severity: {summary.get('low_severity', 0)}")
        response.append("")
        response.append("=" * 80)
        response.append("")
        
        # Process each issue
        for idx, issue in enumerate(issues, 1):
            file_path = issue.get('file', 'Unknown')
            line_number = issue.get('line', 0)
            function = issue.get('function', 'Unknown')
            checker = issue.get('checker', 'Unknown')
            description = issue.get('description', 'No description')
            severity = issue.get('severity', 'Unknown')
            category = issue.get('category', 'Unknown')
            cwe = issue.get('cwe', 'N/A')
            recommendation = issue.get('recommendation', 'No recommendation provided')
            
            response.append(f"ISSUE #{idx}: {checker}")
            response.append("-" * 80)
            response.append(f"File: {file_path}")
            response.append(f"Line: {line_number}")
            response.append(f"Function: {function}")
            response.append(f"Severity: {severity}")
            response.append(f"Category: {category}")
            response.append(f"CWE: {cwe}")
            response.append("")
            response.append(f"Description: {description}")
            response.append("")
            response.append(f"Recommendation: {recommendation}")
            response.append("")
            
            # Get file context
            context = get_file_context(file_path, line_number, context_lines=5, project_root=project_root)
            
            if "error" in context:
                response.append(f"Context: {context['error']}")
            else:
                response.append(f"CODE CONTEXT (Lines {context['start_line']}-{context['end_line']}):")
                response.append("-" * 80)
                
                # Add line numbers to context
                context_lines = context['context'].split('\n')
                for i, line in enumerate(context_lines):
                    if line or i < len(context_lines) - 1:  # Skip only the last empty line
                        line_num = context['start_line'] + i
                        marker = ">>> " if line_num == line_number else "    "
                        response.append(f"{marker}{line_num:4d} | {line}")
                
                response.append("-" * 80)
                response.append(f"Issue Line: {context['issue_line']}")
            
            response.append("")
            response.append("=" * 80)
            response.append("")
        
        # Add fixing instructions
        response.append("FIXING INSTRUCTIONS:")
        response.append("-" * 80)
        response.append("To fix these issues:")
        response.append("1. Review each issue's description and recommendation")
        response.append("2. Navigate to the specified file and line number")
        response.append("3. Apply the recommended fix based on the issue type")
        response.append("4. Test the changes to ensure no functionality is broken")
        response.append("5. Re-run Coverity analysis to verify the fix")
        response.append("")
        response.append("Common Fixes by Issue Type:")
        response.append("- RESOURCE_LEAK: Use context managers (with statement)")
        response.append("- NULL_POINTER: Add null/None checks before accessing")
        response.append("- UNINITIALIZED_VARIABLE: Initialize variables at declaration")
        response.append("- BUFFER_OVERFLOW: Add bounds checking and validation")
        response.append("- MEMORY_LEAK: Implement proper cleanup and garbage collection")
        response.append("- FORMAT_STRING_VULNERABILITY: Use parameterized formatting")
        response.append("- PATH_TRAVERSAL: Validate and sanitize file paths")
        response.append("- SQL_INJECTION: Use parameterized queries")
        response.append("")
        
        return "\n".join(response)
        
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON format in {coverity_json_path}: {str(e)}"
    except Exception as e:
        return f"Error processing Coverity issues: {str(e)}"

@mcp.tool()
def get_issue_by_file(file_path: str, coverity_json_path: str = "coverity_issues.json") -> str:
    """
    Get all Coverity issues for a specific file.
    
    Args:
        file_path: Path to the file to check (e.g., "app/main.py")
        coverity_json_path: Path to the Coverity issues JSON file (default: coverity_issues.json)
    
    Returns:
        All issues found in the specified file with context
    """
    try:
        project_root = os.getcwd()
        json_full_path = os.path.join(project_root, coverity_json_path)
        
        if not os.path.exists(json_full_path):
            return f"Error: Coverity issues file not found at {coverity_json_path}"
        
        with open(json_full_path, 'r', encoding='utf-8') as f:
            coverity_data = json.load(f)
        
        issues = coverity_data.get('issues', [])
        file_issues = [issue for issue in issues if issue.get('file') == file_path]
        
        if not file_issues:
            return f"No Coverity issues found in file: {file_path}"
        
        response = []
        response.append(f"COVERITY ISSUES IN {file_path}")
        response.append("=" * 80)
        response.append(f"Total Issues in File: {len(file_issues)}")
        response.append("")
        
        for idx, issue in enumerate(file_issues, 1):
            line_number = issue.get('line', 0)
            function = issue.get('function', 'Unknown')
            checker = issue.get('checker', 'Unknown')
            description = issue.get('description', 'No description')
            severity = issue.get('severity', 'Unknown')
            recommendation = issue.get('recommendation', 'No recommendation provided')
            
            response.append(f"ISSUE #{idx}: {checker} (Line {line_number})")
            response.append("-" * 80)
            response.append(f"Function: {function}")
            response.append(f"Severity: {severity}")
            response.append(f"Description: {description}")
            response.append(f"Recommendation: {recommendation}")
            response.append("")
            
            # Get context
            context = get_file_context(file_path, line_number, context_lines=3, project_root=project_root)
            if "error" not in context:
                response.append(f"Code Context (Lines {context['start_line']}-{context['end_line']}):")
                context_lines = context['context'].split('\n')
                for i, line in enumerate(context_lines):
                    if line or i < len(context_lines) - 1:
                        line_num = context['start_line'] + i
                        marker = ">>> " if line_num == line_number else "    "
                        response.append(f"{marker}{line_num:4d} | {line}")
            
            response.append("")
            response.append("=" * 80)
            response.append("")
        
        return "\n".join(response)
        
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    # Run the FastMCP server
    mcp.run()

