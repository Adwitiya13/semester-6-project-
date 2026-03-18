#!/usr/bin/env python3
"""
Upload files to GitHub - handles empty repositories
"""

import os
import base64
import requests
from pathlib import Path

def main():
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable is not set")
    REPO_OWNER = "Adwitiya13"
    REPO_NAME = "semester-6-project-"
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }
    
    project_dir = r"c:\Users\Adwitiya Koley\OneDrive\Desktop\Vulnerability tool\Website-Vulnerability-Analyzer-main"
    os.chdir(project_dir)
    
    print("\n" + "="*70)
    print("UPLOADING TO GITHUB")
    print("="*70 + "\n")
    
    print("[*] Repository: https://github.com/Adwitiya13/semester-6-project-")
    print("[*] Uploading files...\n")
    
    uploaded = 0
    failed = 0
    
    # Files to upload
    files_list = [
        "app.py",
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
        "README_WEB.md",
        "README.md",
        "README_ADVANCED.md",
        "QUICKSTART.md",
        "config.yml",
        "config_example.yml",
    ]
    
    print("=== Python & Documentation Files ===")
    for file in files_list:
        if os.path.exists(file):
            try:
                with open(file, 'rb') as f:
                    content = f.read()
                
                b64_content = base64.b64encode(content).decode('utf-8')
                
                # GitHub API endpoint
                url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file}"
                
                # Check if file exists
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
                    "branch": "main"
                }
                
                if sha:
                    payload["sha"] = sha
                
                # Upload
                r = requests.put(url, json=payload, headers=headers, timeout=10)
                
                if r.status_code in [200, 201]:
                    print(f"[✓] {file}")
                    uploaded += 1
                else:
                    error_msg = r.json().get('message', f'Status {r.status_code}')
                    print(f"[✗] {file} - {error_msg}")
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
                    "branch": "main"
                }
                
                if sha:
                    payload["sha"] = sha
                
                r = requests.put(url, json=payload, headers=headers, timeout=10)
                
                if r.status_code in [200, 201]:
                    print(f"[✓] {remote_path}")
                    uploaded += 1
                else:
                    error_msg = r.json().get('message', f'Status {r.status_code}')
                    print(f"[✗] {remote_path} - {error_msg}")
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
    
    print(f"\n[*] Check your repo: https://github.com/Adwitiya13/semester-6-project-")
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Upload cancelled")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
