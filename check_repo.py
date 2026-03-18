import os
import requests

token = os.getenv("GITHUB_TOKEN")
if not token:
    raise ValueError("GITHUB_TOKEN environment variable is not set")
repo = "Adwitiya13/semester-6-project-"

headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
}

# Check repository info
print("=== Repository Info ===")
url = f"https://api.github.com/repos/{repo}"
r = requests.get(url, headers=headers)
repo_data = r.json()
print(f"Repository: {repo_data.get('full_name')}")
print(f"Default Branch: {repo_data.get('default_branch')}")
print(f"Is Empty: {repo_data.get('size') == 0}")

# Check branches
print("\n=== Branches ===")
url = f"https://api.github.com/repos/{repo}/branches"
r = requests.get(url, headers=headers)
branches = r.json()
print(f"Branches: {[b.get('name') for b in branches]}")

# If no branches, try to create initial file on any branch
if not branches:
    print("\n✓ Repository is empty - need to create initial content")
    print("  Trying to create first file on 'main' branch...")
else:
    print(f"\n✓ Default branch is: {repo_data.get('default_branch')}")
    print(f"  Use this branch: {repo_data.get('default_branch')}")
