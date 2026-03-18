import requests
import base64

token = "REDACTED"
repo = "Adwitiya13/semester-6-project-"

headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
}

# Test if repo is accessible
url = f"https://api.github.com/repos/{repo}"
r = requests.get(url, headers=headers)
print(f"Repo Check Status: {r.status_code}")
print(f"Response: {r.text[:300]}")

if r.status_code == 200:
    print("\n✓ Repo exists and is accessible!")
    
    # Try uploading a test file
    print("\nAttempting to upload test file...")
    
    test_content = b"# Test Upload"
    b64_content = base64.b64encode(test_content).decode('utf-8')
    
    upload_url = f"https://api.github.com/repos/{repo}/contents/TEST_UPLOAD.md"
    upload_headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }
    
    payload = {
        "message": "Test upload",
        "content": b64_content,
        "branch": "main"
    }
    
    import json
    upload_response = requests.put(upload_url, json=payload, headers=upload_headers)
    print(f"Upload Status: {upload_response.status_code}")
    print(f"Upload Response: {upload_response.text[:500]}")
    
else:
    print(f"\n✗ Repo error: {r.json().get('message', 'Unknown error')}")
