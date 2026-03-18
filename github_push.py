#!/usr/bin/env python3
"""
Push files to GitHub using GitHub API
Requires: GitHub Personal Access Token
"""

import os
import json
import base64
import requests
from pathlib import Path

def push_to_github():
    """Push files to GitHub repository"""
    
    # Configuration
    GITHUB_TOKEN = input("Enter your GitHub Personal Access Token: ")
    REPO_OWNER = "Adwitiya13"
    REPO_NAME = "semester-6-project-"
    BRANCH = "main"
    
    # Project directory
    project_dir = r"c:\Users\Adwitiya Koley\OneDrive\Desktop\Vulnerability tool\Website-Vulnerability-Analyzer-main"
    
    # GitHub API base URL
    API_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
    
    # Headers for authentication
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    print("\n" + "="*70)
    print("PUSHING TO GITHUB")
    print("="*70)
    
    # Files to upload (excluding certain files)
    exclude_dirs = {'.git', '__pycache__', '.vscode', 'uploads', '.pytest_cache'}
    exclude_files = {'.gitignore', 'push_to_github.py', '.DS_Store'}
    
    # Get all files to upload
    files_to_upload = []
    
    for root, dirs, files in os.walk(project_dir):
        # Remove excluded directories from traversal
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file not in exclude_files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, project_dir)
                files_to_upload.append((file_path, relative_path))
    
    print(f"\n[*] Found {len(files_to_upload)} files to upload")
    
    # Upload each file
    success_count = 0
    failed_count = 0
    
    for file_path, relative_path in sorted(files_to_upload):
        try:
            # Convert path to forward slashes for GitHub
            github_path = relative_path.replace('\\', '/')
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Encode to base64
            encoded_content = base64.b64encode(file_content).decode('utf-8')
            
            # Prepare upload data
            upload_url = f"{API_URL}/{github_path}"
            data = {
                "message": f"Add {github_path}",
                "content": encoded_content,
                "branch": BRANCH
            }
            
            # Check if file exists
            get_response = requests.get(upload_url, headers=headers)
            
            if get_response.status_code == 200:
                # File exists, add SHA for update
                sha = get_response.json().get('sha')
                data['sha'] = sha
            
            # Upload/Update file
            response = requests.put(upload_url, json=data, headers=headers)
            
            if response.status_code in [201, 200]:
                print(f"[✓] {github_path}")
                success_count += 1
            else:
                print(f"[✗] {github_path} - Status: {response.status_code}")
                if response.text:
                    print(f"    Error: {response.text[:100]}")
                failed_count += 1
        
        except Exception as e:
            print(f"[✗] {relative_path} - Exception: {str(e)}")
            failed_count += 1
    
    print("\n" + "="*70)
    print(f"Upload Complete!")
    print(f"✓ Successful: {success_count}")
    print(f"✗ Failed: {failed_count}")
    print(f"\nRepository: https://github.com/{REPO_OWNER}/{REPO_NAME}")
    print("="*70)


if __name__ == "__main__":
    try:
        push_to_github()
    except KeyboardInterrupt:
        print("\n[!] Upload cancelled by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
