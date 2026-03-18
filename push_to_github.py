#!/usr/bin/env python3
"""
Script to push the Vulnerability Analyzer to GitHub
"""

import subprocess
import os
import sys

def run_command(cmd, description):
    """Run a shell command and handle errors"""
    print(f"\n[*] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[✓] {description} - Success")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            print(f"[✗] {description} - Failed")
            if result.stderr:
                print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"[✗] Exception: {str(e)}")
        return False

def main():
    os.chdir(r"c:\Users\Adwitiya Koley\OneDrive\Desktop\Vulnerability tool\Website-Vulnerability-Analyzer-main")
    
    repo_url = "https://github.com/Adwitiya13/semester-6-project-.git"
    
    print("="*70)
    print("PUSHING VULNERABILITY ANALYZER TO GITHUB")
    print("="*70)
    
    # Configure git
    run_command('git config --global user.name "Adwitiya Koley"', "Setting git username")
    run_command('git config --global user.email "adwitiya@example.com"', "Setting git email")
    
    # Initialize repo if not already done
    if not os.path.exists(".git"):
        run_command("git init", "Initializing git repository")
    
    # Add all files
    run_command("git add .", "Adding all files to staging area")
    
    # Commit
    run_command('git commit -m "Add Vulnerability Analyzer v2.0 - Web Edition with RSA/DSA Cryptography, Password Analysis, Risk Assessment, and Compliance Checking"', "Creating initial commit")
    
    # Add remote
    run_command(f'git remote remove origin 2>nul || echo "No existing remote"', "Removing existing remote")
    run_command(f'git remote add origin "{repo_url}"', "Adding GitHub remote")
    
    # Push to GitHub
    success = run_command("git push -u origin master", "Pushing to GitHub (master branch)")
    
    if not success:
        print("\n[*] Trying main branch instead of master...")
        run_command("git push -u origin main", "Pushing to GitHub (main branch)")
    
    print("\n" + "="*70)
    print("[✓] Push complete! Check your GitHub repo:")
    print(f"    {repo_url}")
    print("="*70)

if __name__ == "__main__":
    main()
