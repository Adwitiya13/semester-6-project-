#!/usr/bin/env python3
"""
File Security Analyzer - Analyze files for security issues
"""

import os
import hashlib
import json
from typing import Dict, List
from pathlib import Path

class FileSecurityAnalyzer:
    """Analyze file integrity, permissions, and content security"""
    
    def __init__(self):
        self.file_vulnerabilities = []
        self.dangerous_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js',
            '.jar', '.app', '.apk', '.zip', '.rar', '.7z'
        }
        self.dangerous_mime_types = {
            'application/x-executable',
            'application/x-msdownload',
            'application/x-msdos-program',
            'application/x-shellscript'
        }
    
    def calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> Dict:
        """Calculate file hash for integrity verification"""
        try:
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            
            return {
                'algorithm': algorithm,
                'hash': hash_obj.hexdigest(),
                'status': '✔ Hash calculated'
            }
        except Exception as e:
            return {
                'algorithm': algorithm,
                'error': str(e),
                'status': '✗ Unable to calculate hash'
            }
    
    def check_file_permissions(self, file_path: str) -> Dict:
        """Check file permissions for security issues"""
        try:
            file_stat = os.stat(file_path)
            mode = file_stat.st_mode
            
            # Check if world-readable/writable
            is_world_readable = bool(mode & 0o044)
            is_world_writable = bool(mode & 0o022)
            is_executable = bool(mode & 0o111)
            
            issues = []
            
            if is_world_readable:
                issues.append('File is world-readable')
            
            if is_world_writable:
                issues.append('File is world-writable - CRITICAL RISK')
            
            if is_executable and 'password' in file_path.lower():
                issues.append('Executable file with password in name')
            
            return {
                'file': os.path.basename(file_path),
                'permissions': oct(mode)[-3:],
                'is_world_readable': is_world_readable,
                'is_world_writable': is_world_writable,
                'is_executable': is_executable,
                'issues': issues,
                'status': '✔ Secure' if not issues else '✗ Security issues found'
            }
        except Exception as e:
            return {
                'error': str(e),
                'status': '✗ Unable to check permissions'
            }
    
    def analyze_file_content(self, file_path: str) -> Dict:
        """Analyze file content for security issues"""
        issues = []
        sensitive_patterns = {
            'api_key': r'[ap]_?[a-z]*_?[0-9a-z]{20,}',
            'password': r'password\s*[:=]\s*["\']?[^"\'\s]+',
            'private_key': r'-----BEGIN.*PRIVATE KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'secret': r'secret\s*[:=]\s*["\']?[^"\'\s]+'
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            import re
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    issues.append({
                        'type': pattern_name,
                        'content_snippet': match.group(0)[:50],
                        'severity': 'Critical'
                    })
            
            return {
                'file': os.path.basename(file_path),
                'issues_found': len(issues),
                'issues': issues,
                'status': '✔ No sensitive data' if not issues else '✗ Sensitive data detected'
            }
        except Exception as e:
            return {
                'error': str(e),
                'status': '✗ Unable to analyze content'
            }
    
    def check_file_extension_safety(self, file_path: str) -> Dict:
        """Check if file extension is dangerous"""
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        is_dangerous = ext in self.dangerous_extensions
        
        return {
            'file': os.path.basename(file_path),
            'extension': ext,
            'is_dangerous': is_dangerous,
            'danger_level': 'Critical' if is_dangerous else 'Safe',
            'status': '✗ Dangerous extension' if is_dangerous else '✔ Safe extension',
            'recommendation': f'Avoid uploading files with {ext} extension' if is_dangerous else None
        }
    
    def scan_directory(self, directory_path: str) -> Dict:
        """Scan an entire directory for security issues"""
        results = {
            'total_files': 0,
            'files_with_issues': 0,
            'dangerous_files': [],
            'files_with_sensitive_data': [],
            'permission_issues': []
        }
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    results['total_files'] += 1
                    
                    # Check extension
                    ext_check = self.check_file_extension_safety(file_path)
                    if ext_check['is_dangerous']:
                        results['dangerous_files'].append(file_path)
                        results['files_with_issues'] += 1
                    
                    # Check content (for smaller files)
                    if os.path.getsize(file_path) < 1_000_000:  # < 1MB
                        content_check = self.analyze_file_content(file_path)
                        if content_check.get('issues_found', 0) > 0:
                            results['files_with_sensitive_data'].append(file_path)
                            results['files_with_issues'] += 1
            
            return results
        except Exception as e:
            return {
                'error': str(e),
                'status': '✗ Unable to scan directory'
            }
    
    def verify_file_integrity(self, file_path: str, expected_hash: str, algorithm: str = 'sha256') -> Dict:
        """Verify file integrity using hash comparison"""
        hash_result = self.calculate_file_hash(file_path, algorithm)
        
        if 'hash' in hash_result:
            is_valid = hash_result['hash'] == expected_hash
            return {
                'file': os.path.basename(file_path),
                'algorithm': algorithm,
                'calculated_hash': hash_result['hash'],
                'expected_hash': expected_hash,
                'is_valid': is_valid,
                'status': '✔ Integrity verified' if is_valid else '✗ Integrity check failed'
            }
        else:
            return {
                'error': 'Unable to calculate hash',
                'status': '✗ Verification failed'
            }
    
    def generate_file_security_report(self, file_path: str) -> str:
        """Generate comprehensive file security report"""
        report = "=" * 60 + "\n"
        report += "FILE SECURITY ANALYSIS REPORT\n"
        report += "=" * 60 + "\n\n"
        
        # Check permissions
        perm_check = self.check_file_permissions(file_path)
        report += "PERMISSIONS:\n"
        report += f"  File: {perm_check.get('file', 'N/A')}\n"
        report += f"  Permissions: {perm_check.get('permissions', 'N/A')}\n"
        report += f"  Status: {perm_check.get('status', 'N/A')}\n\n"
        
        # Check extension
        ext_check = self.check_file_extension_safety(file_path)
        report += "FILE EXTENSION:\n"
        report += f"  Extension: {ext_check.get('extension', 'N/A')}\n"
        report += f"  Status: {ext_check.get('status', 'N/A')}\n\n"
        
        # Check content
        content_check = self.analyze_file_content(file_path)
        report += f"SENSITIVE DATA: {content_check.get('status', 'N/A')}\n"
        
        return report
