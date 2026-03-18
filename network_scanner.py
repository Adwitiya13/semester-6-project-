#!/usr/bin/env python3
"""
Network Security Scanner - Identify network and web vulnerabilities
"""

import re
from typing import Dict, List
from urllib.parse import urlparse

class NetworkSecurityScanner:
    """Scan networks and web applications for security issues"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.recommendations = []
    
    def check_ssl_tls(self, url: str) -> Dict:
        """Check SSL/TLS security"""
        parsed = urlparse(url)
        is_https = parsed.scheme == 'https'
        
        result = {
            'protocol': parsed.scheme.upper(),
            'is_https': is_https,
            'status': '✔ Secure' if is_https else '✗ Insecure',
            'issue': None,
            'recommendation': None
        }
        
        if not is_https:
            result['issue'] = 'Connection is not encrypted (HTTP instead of HTTPS)'
            result['recommendation'] = 'Enable HTTPS/TLS encryption for all communications'
            self.vulnerabilities.append(result['issue'])
        
        return result
    
    def check_headers(self, headers: Dict) -> Dict:
        """Check for important security headers"""
        critical_headers = {
            'Strict-Transport-Security': {
                'name': 'HSTS',
                'importance': 'Critical',
                'purpose': 'Force HTTPS connections'
            },
            'Content-Security-Policy': {
                'name': 'CSP',
                'importance': 'High',
                'purpose': 'Prevent XSS attacks'
            },
            'X-Content-Type-Options': {
                'name': 'XCTO',
                'importance': 'High',
                'purpose': 'Prevent MIME sniffing'
            },
            'X-Frame-Options': {
                'name': 'XFO',
                'importance': 'High',
                'purpose': 'Prevent clickjacking'
            },
            'X-XSS-Protection': {
                'name': 'XXP',
                'importance': 'Medium',
                'purpose': 'Enable XSS protection'
            }
        }
        
        missing_headers = []
        present_headers = []
        
        for header, info in critical_headers.items():
            if header in headers or header.lower() in {k.lower(): k for k in headers}:
                present_headers.append(header)
                result = {
                    'header': header,
                    'status': '✔ Present',
                    'value': headers.get(header, 'Set'),
                    'importance': info['importance']
                }
            else:
                missing_headers.append(header)
                result = {
                    'header': header,
                    'status': '✗ Missing',
                    'importance': info['importance'],
                    'purpose': info['purpose']
                }
                self.vulnerabilities.append(f'Missing security header: {header}')
        
        return {
            'present_count': len(present_headers),
            'missing_count': len(missing_headers),
            'missing_headers': missing_headers,
            'security_score': (len(present_headers) / len(critical_headers)) * 100
        }
    
    def check_sql_injection_vectors(self, form_data: List[str]) -> Dict:
        """Analyze forms for SQL injection vulnerabilities"""
        sql_patterns = [
            r"union\s+select",
            r"select\s+\*\s+from",
            r"drop\s+table",
            r"insert\s+into",
            r"update\s+",
            r"delete\s+from",
            r"exec\s*\(",
            r"execute\s*\("
        ]
        
        vulnerabilities = []
        
        for form_field in form_data:
            for pattern in sql_patterns:
                if re.search(pattern, form_field, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'SQL Injection Risk',
                        'location': form_field,
                        'pattern': pattern,
                        'severity': 'Critical'
                    })
        
        return {
            'sql_injection_risks': vulnerabilities,
            'total_risks': len(vulnerabilities),
            'status': '✔ No SQL injection patterns found' if not vulnerabilities else '✗ Potential SQL injection detected'
        }
    
    def check_xss_vulnerabilities(self, html_content: str) -> Dict:
        """Check for XSS (Cross-Site Scripting) vulnerabilities"""
        xss_patterns = {
            'script_tags': r'<script[^>]*>.*?</script>',
            'event_handlers': r'on\w+\s*=\s*["\']?javascript:',
            'javascript_protocol': r'href\s*=\s*["\']?javascript:',
            'dangerous_functions': r'eval\s*\(|innerHTML\s*=|document\.write'
        }
        
        vulnerabilities = []
        
        for vuln_type, pattern in xss_patterns.items():
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                vulnerabilities.append({
                    'type': 'XSS Vulnerability',
                    'category': vuln_type,
                    'pattern': match.group(0)[:100],
                    'severity': 'High'
                })
        
        return {
            'xss_vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'status': '✔ No XSS patterns found' if not vulnerabilities else '✗ Potential XSS found'
        }
    
    def check_authentication_mechanisms(self, headers: Dict, html: str) -> Dict:
        """Check authentication and authorization mechanisms"""
        issues = []
        
        # Check for WWW-Authenticate header
        has_auth_header = 'www-authenticate' in {k.lower() for k in headers}
        
        # Check for security tokens
        has_csrf_token = 'csrf' in html.lower() or '_token' in html.lower()
        has_auth_token = 'authorization' in {k.lower() for k in headers}
        
        if not has_auth_header:
            issues.append('No authentication mechanism detected')
        
        if not has_csrf_token:
            issues.append('No CSRF token detected in forms')
        
        return {
            'has_authentication': has_auth_header,
            'has_csrf_protection': has_csrf_token,
            'has_auth_header': has_auth_token,
            'issues': issues,
            'status': '✔ Secure' if (has_auth_header and has_csrf_token) else '⚠ Review needed'
        }
    
    def check_cors_policy(self, headers: Dict) -> Dict:
        """Check CORS (Cross-Origin Resource Sharing) policies"""
        cors_headers = {
            'Access-Control-Allow-Origin': None,
            'Access-Control-Allow-Methods': None,
            'Access-Control-Allow-Headers': None,
            'Access-Control-Max-Age': None
        }
        
        found_cors = {k: v for k, v in headers.items() if k.startswith('Access-Control')}
        
        if found_cors.get('Access-Control-Allow-Origin') == '*':
            issue = 'CORS allows requests from any origin'
            self.vulnerabilities.append(issue)
        
        return {
            'has_cors_policy': len(found_cors) > 0,
            'cors_policy': found_cors or 'No CORS headers found',
            'status': '⚠ Verify CORS policy' if found_cors else '✔ No CORS headers (if intentional)'
        }
    
    def generate_security_report(self) -> str:
        """Generate network security report"""
        report = "=" * 60 + "\n"
        report += "NETWORK SECURITY SCAN REPORT\n"
        report += "=" * 60 + "\n\n"
        
        if self.vulnerabilities:
            report += f"Vulnerabilities Found: {len(self.vulnerabilities)}\n"
            for vuln in self.vulnerabilities:
                report += f"  ✗ {vuln}\n"
        else:
            report += "✔ No vulnerabilities detected\n"
        
        return report
