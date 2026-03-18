#!/usr/bin/env python3
"""
Simple script to upload files to GitHub using GitHub API
No Git installation required
"""

import os
import json
import base64
import sys
import requests
from pathlib import Path

def main():
    print("\n" + "="*70)
    print("UPLOAD FILES TO GITHUB")
    print("="*70 + "\n")
    
    # Get GitHub token from command line or input
    if len(sys.argv) > 1:
        token = sys.argv[1].strip()
    else:
        # Get GitHub token
        print("Get your GitHub Personal Access Token:")
        print("1. Go to: https://github.com/settings/tokens/new")
        print("2. Check 'repo' scope")
        print("3. Generate and copy the token\n")
        
        token = input("Paste your GitHub Personal Access Token: ").strip()
    
    if not token:
        print("[!] No token provided. Exiting.")
        return
    
    # Repository details
    REPO_OWNER = "Adwitiya13"
    REPO_NAME = "semester-6-project-"
    BRANCH = "main"
    
    # Headers for API
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }
    
    # Project directory
    project_dir = r"c:\Users\Adwitiya Koley\OneDrive\Desktop\Vulnerability tool\Website-Vulnerability-Analyzer-main"
    os.chdir(project_dir)
    
    print(f"\n[*] Repository: https://github.com/{REPO_OWNER}/{REPO_NAME}")
    print(f"[*] Branch: {BRANCH}")
    print("[*] Uploading files...\n")
    
    uploaded = 0
    failed = 0
    
    # Files to upload
    files_to_upload = [
        # Main app
        "app.py",
        # Python modules
        "crypto_toolkit.py",
        "password_analyzer.py",
        "network_scanner.py",
        "file_analyzer.py",
        "grc_engine.py",
        "risk_scorer.py",
        "report_generator.py",
        "otp_sharing.py",
        "Website_Analyzer_Advanced.py",
        "Website_Analyzer.py",
        # Docs
        "README_WEB.md",
        "README.md",
        "README_ADVANCED.md",
        "QUICKSTART.md",
        # Config
        "config.yml",
        "config_example.yml",
    ]
    
    # Upload main files
    print("=== Python & Documentation Files ===")
    for file in files_to_upload:
        if os.path.exists(file):
            try:
                # Read file
                with open(file, 'rb') as f:
                    content = f.read()
                
                # Encode to base64
                b64_content = base64.b64encode(content).decode('utf-8')
                
                # GitHub API endpoint
                url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file}"
                
                # Check if file exists (get SHA for update)
                sha = None
                try:
                    r = requests.get(url, headers=headers, timeout=5)
                    if r.status_code == 200:
                        sha = r.json().get('sha')
                except:
                    pass
                
                # Prepare payload
                payload = {
                    "message": f"Add {file}",
                    "content": b64_content,
                    "branch": BRANCH
                }
                
                if sha:
                    payload["sha"] = sha
                
                # Upload
                r = requests.put(url, json=payload, headers=headers, timeout=10)
                
                if r.status_code in [200, 201]:
                    print(f"[✓] {file}")
                    uploaded += 1
                elif r.status_code == 401:
                    print(f"[✗] {file} - Authentication failed (bad token)")
                    failed += 1
                else:
                    print(f"[✗] {file} - Status {r.status_code}")
                    failed += 1
            
            except Exception as e:
                print(f"[✗] {file} - {str(e)[:40]}")
                failed += 1
    
    # Upload templates
    print("\n=== HTML Templates ===")
    templates = [
        "base.html", "index.html", "demo.html", "password.html",
        "analyzer.html", "crypto.html", "file.html", "risk.html",
        "compliance.html", "reports.html"
    ]
    
    for template in templates:
        file_path = f"templates\\{template}"
        remote_path = f"templates/{template}"
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                b64_content = base64.b64encode(content).decode('utf-8')
                
                url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{remote_path}"
                
                sha = None
                try:
                    r = requests.get(url, headers=headers, timeout=5)
                    if r.status_code == 200:
                        sha = r.json().get('sha')
                except:
                    pass
                
                payload = {
                    "message": f"Add {remote_path}",
                    "content": b64_content,
                    "branch": BRANCH
                }
                
                if sha:
                    payload["sha"] = sha
                
                r = requests.put(url, json=payload, headers=headers, timeout=10)
                
                if r.status_code in [200, 201]:
                    print(f"[✓] {remote_path}")
                    uploaded += 1
                elif r.status_code == 401:
                    print(f"[✗] {remote_path} - Authentication failed")
                    failed += 1
                else:
                    print(f"[✗] {remote_path} - Status {r.status_code}")
                    failed += 1
            
            except Exception as e:
                print(f"[✗] {remote_path} - {str(e)[:40]}")
                failed += 1
    
    # Summary
    print("\n" + "="*70)
    print("UPLOAD COMPLETE")
    print("="*70 + "\n")
    
    print(f"✓ Successfully uploaded: {uploaded} files")
    if failed > 0:
        print(f"✗ Failed: {failed} files")
    
    print(f"\n[*] Repository: https://github.com/{REPO_OWNER}/{REPO_NAME}")
    print(f"[*] View your code: {f'https://github.com/{REPO_OWNER}/{REPO_NAME}'}")
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Upload cancelled by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
