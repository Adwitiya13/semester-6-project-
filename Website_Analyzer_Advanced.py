#!/usr/bin/env python3
"""
Website Vulnerability Analyzer - Complete Security Assessment Tool
Integrated with advanced cryptography, risk scoring, and compliance frameworks
"""

import argparse
import validators
import requests
import yaml
import json
import sys
from typing import Dict, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment
from datetime import datetime

# Import custom modules
from crypto_toolkit import RSA, DSA
from password_analyzer import PasswordAnalyzer
from network_scanner import NetworkSecurityScanner
from file_analyzer import FileSecurityAnalyzer
from grc_engine import GRCComplianceEngine
from risk_scorer import RiskScoringSystem
from report_generator import SecurityReportGenerator
from otp_sharing import OTPManager, SecureReportSharing


class ComprehensiveSecurityAnalyzer:
    """Complete security assessment platform"""
    
    def __init__(self):
        self.password_analyzer = PasswordAnalyzer()
        self.network_scanner = NetworkSecurityScanner()
        self.file_analyzer = FileSecurityAnalyzer()
        self.grc_engine = GRCComplianceEngine()
        self.risk_scorer = RiskScoringSystem()
        self.report_generator = SecurityReportGenerator()
        self.otp_manager = OTPManager()
        self.report_sharer = SecureReportSharing()
        
        self.findings = {
            'vulnerabilities': [],
            'cryptography_analysis': {},
            'password_strength': {},
            'network_security': {},
            'file_security': {},
            'risk_assessment': {},
            'compliance': {}
        }
    
    def analyze_website(self, url: str) -> Dict:
        """Comprehensive website security analysis"""
        print(f"\n[*] Analyzing website: {url}")
        
        try:
            # Validate URL
            if not validators.url(url):
                print("[-] Invalid URL format")
                return {}
            
            # Network analysis - SSL/TLS
            print("[*] Checking SSL/TLS configuration...")
            ssl_results = self.network_scanner.check_ssl_tls(url)
            self.findings['network_security']['ssl_tls'] = ssl_results
            
            # Fetch page
            headers = {'User-Agent': 'Mozilla/5.0 (Security Assessment Tool)'}
            response = requests.get(url, headers=headers, timeout=10)
            html_content = response.text
            
            # Check headers
            print("[*] Analyzing security headers...")
            header_results = self.network_scanner.check_headers(dict(response.headers))
            self.findings['network_security']['headers'] = header_results
            
            # Parse HTML
            parsed_html = BeautifulSoup(html_content, 'html.parser')
            
            # Extract forms
            forms = parsed_html.find_all('form')
            print(f"[+] Found {len(forms)} form(s)")
            
            # Get comments
            comments = parsed_html.find_all(string=lambda text: isinstance(text, Comment))
            print(f"[+] Found {len(comments)} HTML comment(s)")
            
            # Check for vulnerable patterns
            print("[*] Checking for vulnerability patterns...")
            
            # XSS check
            xss_results = self.network_scanner.check_xss_vulnerabilities(html_content)
            self.findings['network_security']['xss'] = xss_results
            
            # Authentication check
            auth_results = self.network_scanner.check_authentication_mechanisms(
                dict(response.headers), html_content
            )
            self.findings['network_security']['authentication'] = auth_results
            
            # CORS check
            cors_results = self.network_scanner.check_cors_policy(dict(response.headers))
            self.findings['network_security']['cors'] = cors_results
            
            return self.findings
            
        except Exception as e:
            print(f"[-] Error analyzing website: {str(e)}")
            return {}
    
    def analyze_password(self, password: str = None) -> Dict:
        """Analyze password strength"""
        if password is None:
            print("[*] Generating sample passwords for analysis...")
            test_passwords = [
                "password123",
                "Str0ng!Pass#2024",
                "MyP@ssw0rd",
                "Random1234"
            ]
        else:
            test_passwords = [password]
        
        results = []
        for pwd in test_passwords:
            analysis = self.password_analyzer.analyze_password(pwd)
            results.append(analysis)
            
            print(f"\n[*] Password Analysis: {pwd[:5]}****")
            print(f"    Strength: {analysis['strength_level']} {analysis['color_indicator']}")
            print(f"    Score: {analysis['strength_score']}/10")
            print(f"    Entropy: {analysis['entropy_bits']} bits")
            print(f"    Crack Time: {analysis['crack_time_estimate']}")
        
        self.findings['password_strength'] = results
        return results
    
    def analyze_rsa_encryption(self, message: int = None) -> Dict:
        """Analyze RSA encryption"""
        print("\n[*] RSA Cryptography Analysis")
        print("[*] Generating RSA key pair...")
        
        rsa = RSA(key_size=2048)
        
        if message is None:
            message = 123456789  # Sample message
        
        print(f"[+] Original message: {message}")
        
        # Encrypt
        ciphertext = rsa.encrypt(message)
        print(f"[+] Encrypted: {ciphertext}")
        
        # Decrypt
        decrypted = rsa.decrypt(ciphertext)
        print(f"[+] Decrypted: {decrypted}")
        
        # Key strength analysis
        strength = rsa.get_key_strength()
        
        result = {
            'algorithm': 'RSA',
            'key_size': strength['key_size'],
            'status': strength['status'],
            'public_key': str(strength['public_key']),
            'message': message,
            'ciphertext': ciphertext,
            'decrypted': decrypted,
            'encryption_success': decrypted == message,
            'recommendation': strength['recommendation']
        }
        
        self.findings['cryptography_analysis']['rsa'] = result
        return result
    
    def analyze_dsa_signing(self, message: str = None) -> Dict:
        """Analyze DSA digital signatures"""
        print("\n[*] DSA Digital Signature Analysis")
        print("[*] Generating DSA key pair...")
        
        dsa = DSA(key_size=1024)
        
        if message is None:
            message = "Security Assessment Sample Message"
        
        print(f"[+] Message: {message}")
        
        # Sign message
        r, s = dsa.sign(message)
        print(f"[+] Signature: r={r}, s={s}")
        
        # Verify signature
        is_valid = dsa.verify(message, (r, s))
        print(f"[+] Signature verification: {'✔ Valid' if is_valid else '✗ Invalid'}")
        
        # Try with tampered message
        tampered = message + " TAMPERED"
        is_tampered_valid = dsa.verify(tampered, (r, s))
        print(f"[+] Tampered message verification: {'✔ Valid' if is_tampered_valid else '✗ Invalid (Expected)'}")
        
        strength = dsa.get_signature_strength()
        
        result = {
            'algorithm': 'DSA',
            'key_size': strength['key_size'],
            'hash_algorithm': strength['hash_algorithm'],
            'message': message,
            'signature_r': r,
            'signature_s': s,
            'signature_valid': is_valid,
            'tampered_detection': not is_tampered_valid,
            'status': strength['status'],
            'recommendation': strength['recommendation']
        }
        
        self.findings['cryptography_analysis']['dsa'] = result
        return result
    
    def analyze_file_security(self, file_path: str) -> Dict:
        """Analyze file security"""
        print(f"\n[*] File Security Analysis: {file_path}")
        
        import os
        if not os.path.exists(file_path):
            print(f"[-] File not found: {file_path}")
            return {}
        
        results = {
            'permissions': self.file_analyzer.check_file_permissions(file_path),
            'extension': self.file_analyzer.check_file_extension_safety(file_path),
            'content': self.file_analyzer.analyze_file_content(file_path),
            'hash_sha256': self.file_analyzer.calculate_file_hash(file_path, 'sha256')
        }
        
        self.findings['file_security'] = results
        return results
    
    def perform_risk_assessment(self, vulnerabilities: List = None) -> Dict:
        """Perform risk assessment"""
        print("\n[*] Risk Assessment")
        
        if vulnerabilities is None:
            vulnerabilities = [
                {
                    'name': 'Missing HTTPS',
                    'ease_of_exploitation': 0.8,
                    'prevalence': 0.9,
                    'confidentiality_impact': 0.8,
                    'integrity_impact': 0.7,
                    'availability_impact': 0.5
                },
                {
                    'name': 'Missing security headers',
                    'ease_of_exploitation': 0.6,
                    'prevalence': 0.7,
                    'confidentiality_impact': 0.5,
                    'integrity_impact': 0.6,
                    'availability_impact': 0.3
                }
            ]
        
        portfolio_risk = self.risk_scorer.calculate_portfolio_risk(vulnerabilities)
        
        print(f"[+] Total Vulnerabilities: {portfolio_risk['total_vulnerabilities']}")
        print(f"[+] Portfolio Risk Score: {portfolio_risk['portfolio_risk_score']}/10")
        print(f"[+] Portfolio Severity: {portfolio_risk['portfolio_severity']}")
        
        self.findings['risk_assessment'] = portfolio_risk
        return portfolio_risk
    
    def assess_compliance(self) -> Dict:
        """Assess compliance against frameworks"""
        print("\n[*] Compliance Assessment")
        
        vulnerabilities = [
            'SQL Injection in login form',
            'Missing HTTPS on sensitive forms',
            'Weak password policy enforcement'
        ]
        
        assessments = {
            'OWASP': self.grc_engine.assess_owasp_compliance(vulnerabilities),
        }
        
        self.findings['compliance'] = assessments
        return assessments
    
    def generate_comprehensive_report(self, output_file: str = None) -> str:
        """Generate comprehensive security report"""
        print("\n[*] Generating comprehensive report...")
        
        report = "=" * 90 + "\n"
        report += "COMPREHENSIVE SECURITY ASSESSMENT REPORT\n"
        report += "=" * 90 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Cryptography Section
        report += "\n" + "=" * 90 + "\n"
        report += "CRYPTOGRAPHY ANALYSIS\n"
        report += "=" * 90 + "\n"
        
        if 'rsa' in self.findings.get('cryptography_analysis', {}):
            rsa = self.findings['cryptography_analysis']['rsa']
            report += f"RSA Encryption: {rsa['status']}\n"
            report += f"  Key Size: {rsa['key_size']} bits\n"
            report += f"  Encryption Test: {'✔ Passed' if rsa['encryption_success'] else '✗ Failed'}\n"
        
        if 'dsa' in self.findings.get('cryptography_analysis', {}):
            dsa = self.findings['cryptography_analysis']['dsa']
            report += f"DSA Signatures: {dsa['status']}\n"
            report += f"  Hash Algorithm: {dsa['hash_algorithm']}\n"
            report += f"  Signature Verification: {'✔ Valid' if dsa['signature_valid'] else '✗ Invalid'}\n"
            report += f"  Tamper Detection: {'✔ Working' if dsa['tampered_detection'] else '✗ Failed'}\n"
        
        # Password Analysis Section
        report += "\n" + "=" * 90 + "\n"
        report += "PASSWORD STRENGTH ANALYSIS\n"
        report += "=" * 90 + "\n"
        
        for pwd_analysis in self.findings.get('password_strength', []):
            report += f"Password: ****\n"
            report += f"  Strength: {pwd_analysis['strength_level']} {pwd_analysis['color_indicator']}\n"
            report += f"  Score: {pwd_analysis['strength_score']}/10\n"
            report += f"  Entropy: {pwd_analysis['entropy_bits']} bits\n"
            report += f"  Crack Time: {pwd_analysis['crack_time_estimate']}\n"
        
        # Network Security Section
        report += "\n" + "=" * 90 + "\n"
        report += "NETWORK SECURITY ANALYSIS\n"
        report += "=" * 90 + "\n"
        
        net_sec = self.findings.get('network_security', {})
        if 'ssl_tls' in net_sec:
            report += f"SSL/TLS: {net_sec['ssl_tls']['status']}\n"
        
        if 'headers' in net_sec:
            report += f"Security Headers: {net_sec['headers']['security_score']:.1f}/100\n"
        
        if 'xss' in net_sec:
            report += f"XSS Vulnerabilities: {net_sec['xss']['total_vulnerabilities']} found\n"
        
        # Risk Assessment Section
        report += "\n" + "=" * 90 + "\n"
        report += "RISK ASSESSMENT\n"
        report += "=" * 90 + "\n"
        
        risk = self.findings.get('risk_assessment', {})
        if risk:
            report += f"Portfolio Risk Score: {risk.get('portfolio_risk_score', 'N/A')}/10\n"
            report += f"Portfolio Severity: {risk.get('portfolio_severity', 'N/A')}\n"
        
        # Compliance Section
        report += "\n" + "=" * 90 + "\n"
        report += "COMPLIANCE ASSESSMENT\n"
        report += "=" * 90 + "\n"
        
        compliance = self.findings.get('compliance', {})
        for framework, assessment in compliance.items():
            report += f"{framework}: {assessment.get('status', 'Unknown')}\n"
            if 'compliance_score' in assessment:
                report += f"  Score: {assessment['compliance_score']}/100\n"
        
        # Recommendations
        report += "\n" + "=" * 90 + "\n"
        report += "RECOMMENDATIONS\n"
        report += "=" * 90 + "\n"
        
        recommendations = [
            "1. Enable HTTPS/TLS for all communications",
            "2. Implement comprehensive security headers",
            "3. Use strong encryption algorithms (RSA-2048 or higher)",
            "4. Enforce strong password policies",
            "5. Implement Web Application Firewall (WAF)",
            "6. Regular security audits and penetration testing",
            "7. Implement Security Incident Response Plan",
            "8. Enable comprehensive logging and monitoring"
        ]
        
        for rec in recommendations:
            report += f"  {rec}\n"
        
        report += "\n" + "=" * 90 + "\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"[+] Report saved to: {output_file}")
        
        return report
    
    def create_secure_share(self, report_content: str, recipient_email: str = None) -> Dict:
        """Create secure report sharing"""
        print("\n[*] Creating secure report share...")
        
        share = self.report_sharer.create_secure_share(
            report_content,
            recipient_email=recipient_email,
            expiry_hours=24
        )
        
        print(f"[+] Share Token: {share['share_token'][:20]}...")
        print(f"[+] Access Link: {share['access_link']}")
        print(f"[+] OTP: {share['otp']}")
        print(f"[+] Validity: {share['expiry_hours']} hours")
        
        return share


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive Website Vulnerability Analyzer with Cryptography & Compliance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a website
  python Website_Analyzer_Advanced.py https://example.com
  
  # Analyze with password strength testing
  python Website_Analyzer_Advanced.py https://example.com --analyze-passwords
  
  # Analyze with RSA/DSA encryption
  python Website_Analyzer_Advanced.py https://example.com --analyze-crypto
  
  # Perform risk assessment
  python Website_Analyzer_Advanced.py https://example.com --risk-assessment
  
  # Generate comprehensive report
  python Website_Analyzer_Advanced.py https://example.com -o report.txt
  
  # Analyze local file
  python Website_Analyzer_Advanced.py --analyze-file /path/to/file
        """
    )
    
    parser.add_argument('url', nargs='?', help='Website URL to analyze')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0 (Advanced)')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--analyze-passwords', action='store_true', help='Analyze password strength')
    parser.add_argument('--analyze-crypto', action='store_true', help='Analyze RSA & DSA encryption')
    parser.add_argument('--risk-assessment', action='store_true', help='Perform risk assessment')
    parser.add_argument('--compliance', action='store_true', help='Check compliance')
    parser.add_argument('--analyze-file', help='Analyze file security')
    parser.add_argument('--secure-share', action='store_true', help='Create secure OTP share')
    parser.add_argument('--recipient-email', help='Email for secure report sharing')
    parser.add_argument('--demo', action='store_true', help='Run demo analysis')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = ComprehensiveSecurityAnalyzer()
    
    # Demo mode
    if args.demo:
        print("\n" + "=" * 90)
        print("RUNNING COMPREHENSIVE SECURITY ANALYSIS DEMO")
        print("=" * 90)
        
        # Analyze RSA
        print("\n[*] Demo 1: RSA Encryption")
        analyzer.analyze_rsa_encryption(message=987654321)
        
        # Analyze DSA
        print("\n[*] Demo 2: DSA Digital Signatures")
        analyzer.analyze_dsa_signing(message="Important Security Document")
        
        # Analyze passwords
        print("\n[*] Demo 3: Password Strength Analysis")
        analyzer.analyze_password()
        
        # Risk assessment
        print("\n[*] Demo 4: Risk Assessment")
        analyzer.perform_risk_assessment()
        
        # Generate report
        print("\n[*] Demo 5: Generating Report")
        report = analyzer.generate_comprehensive_report(args.output)
        print(report)
        
        return
    
    # File analysis mode
    if args.analyze_file:
        analyzer.analyze_file_security(args.analyze_file)
        if args.output:
            report = analyzer.generate_comprehensive_report(args.output)
        return
    
    # Website analysis mode
    if args.url:
        if not validators.url(args.url):
            print("[-] Invalid URL format")
            sys.exit(1)
        
        print("\n" + "=" * 90)
        print("COMPREHENSIVE WEB APPLICATION SECURITY ANALYSIS")
        print("=" * 90)
        
        # Analyze website
        analyzer.analyze_website(args.url)
        
        # Additional analyses
        if args.analyze_passwords:
            analyzer.analyze_password()
        
        if args.analyze_crypto:
            analyzer.analyze_rsa_encryption()
            analyzer.analyze_dsa_signing()
        
        if args.risk_assessment:
            analyzer.perform_risk_assessment()
        
        if args.compliance:
            analyzer.assess_compliance()
        
        # Generate report
        report = analyzer.generate_comprehensive_report(args.output)
        
        # Secure sharing
        if args.secure_share:
            share = analyzer.create_secure_share(report, args.recipient_email)
            print("\n[+] Secure sharing created!")
            print(f"[+] Instructions:\n{analyzer.report_sharer.generate_secure_sharing_instructions(share['share_token'], share['otp'])}")
        else:
            print(report)
    else:
        if not args.demo and not args.analyze_file:
            parser.print_help()


if __name__ == '__main__':
    main()
