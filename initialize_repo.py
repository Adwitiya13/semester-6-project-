#!/usr/bin/env python3
"""
Initialize empty GitHub repo by creating .gitkeep file first
"""

import base64
import requests

token = "REDACTED"
REPO = "Adwitiya13/semester-6-project-"

headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
}

print("\n[*] Initializing empty repository...")
print("[*] Creating initial commit...\n")

# Step 1: Create .gitkeep to initialize repo
try:
    url = f"https://api.github.com/repos/{REPO}/contents/.gitkeep"
    payload = {
        "message": "Initial commit - Initialize repository",
        "content": base64.b64encode(b"").decode('utf-8'),
        "branch": "main"
    }
    
    r = requests.put(url, json=payload, headers=headers, timeout=10)
    print(f"Initialize repo: Status {r.status_code}")
    
    if r.status_code in [200, 201]:
        print("[✓] Repository initialized successfully!")
        print(f"[✓] 'main' branch created\n")
    else:
        print(f"[✗] Failed: {r.json().get('message', 'Unknown error')}\n")
        
except Exception as e:
    print(f"[✗] Error: {str(e)}\n")

# Step 2: Check repo status
try:
    url = f"https://api.github.com/repos/{REPO}"
    r = requests.get(url, headers=headers)
    data = r.json()
    
    print(f"Repository Status:")
    print(f"  • Name: {data.get('name')}")
    print(f"  • Default Branch: {data.get('default_branch')}")
    print(f"  • Is Empty: {data.get('size') == 0}")
    
    if data.get('size') > 0:
        print(f"\n✓ Repository is now initialized and ready for uploads!")
    
except Exception as e:
    print(f"[!] Error checking status: {str(e)}")
