#!/usr/bin/env python3
"""
GRC Compliance Engine - Governance, Risk, and Compliance framework
"""

from typing import Dict, List
from datetime import datetime

class GRCComplianceEngine:
    """Manage GRC (Governance, Risk, Compliance) assessments"""
    
    def __init__(self):
        self.compliance_frameworks = {
            'OWASP': {
                'controls': [
                    'A01:2021 - Broken Access Control',
                    'A02:2021 - Cryptographic Failures',
                    'A03:2021 - Injection',
                    'A04:2021 - Insecure Design',
                    'A05:2021 - Security Misconfiguration',
                    'A06:2021 - Vulnerable and Outdated Components',
                    'A07:2021 - Authentication Failures',
                    'A08:2021 - Software and Data Integrity Failures',
                    'A09:2021 - Logging and Monitoring Failures',
                    'A10:2021 - Server-Side Request Forgery (SSRF)'
                ],
                'description': 'OWASP Top 10 Web Application Security Risks'
            },
            'NIST': {
                'controls': [
                    'AC - Access Control',
                    'AU - Audit and Accountability',
                    'AT - Awareness and Training',
                    'CA - Security Assessment and Authorization',
                    'CM - Configuration Management',
                    'IA - Identification and Authentication',
                    'IR - Incident Response',
                    'MA - Maintenance',
                    'MP - Media Protection',
                    'PS - Personnel Security',
                    'PE - Physical and Environmental Protection',
                    'PL - Planning',
                    'RA - Risk Assessment',
                    'SA - System and Services Acquisition',
                    'SC - System and Communications Protection',
                    'SI - System and Information Integrity'
                ],
                'description': 'NIST Cybersecurity Framework'
            },
            'ISO27001': {
                'controls': [
                    'Information Security Policies',
                    'Organization of Information Security',
                    'Human Resource Security',
                    'Asset Management',
                    'Access Control',
                    'Cryptography',
                    'Physical and Environmental Security',
                    'Operations Security',
                    'Communications Security',
                    'System Acquisition, Development, and Maintenance',
                    'Supplier Relationships',
                    'Information Security Incident Management',
                    'Business Continuity Management',
                    'Compliance'
                ],
                'description': 'ISO/IEC 27001 Information Security Management'
            },
            'PCI-DSS': {
                'controls': [
                    'Requirement 1: Firewall Configuration',
                    'Requirement 2: Default Passwords',
                    'Requirement 3: Stored Data Protection',
                    'Requirement 4: Transmission Data Protection',
                    'Requirement 5: Malware Protection',
                    'Requirement 6: Secure Development',
                    'Requirement 7: Access Restriction',
                    'Requirement 8: User Identification',
                    'Requirement 9: Physical Access',
                    'Requirement 10: Logging and Monitoring',
                    'Requirement 11: Security Testing',
                    'Requirement 12: Security Policy'
                ],
                'description': 'Payment Card Industry Data Security Standard'
            }
        }
        
        self.compliance_status = {}
    
    def assess_owasp_compliance(self, vulnerabilities: List[str]) -> Dict:
        """Assess compliance against OWASP Top 10"""
        owasp_mapping = {
            'SQL Injection': 'A03:2021 - Injection',
            'XSS': 'A03:2021 - Injection',
            'Broken Authentication': 'A07:2021 - Authentication Failures',
            'Sensitive Data Exposure': 'A02:2021 - Cryptographic Failures',
            'XML External Entity': 'A03:2021 - Injection',
            'Broken Access Control': 'A01:2021 - Broken Access Control',
            'Security Misconfiguration': 'A05:2021 - Security Misconfiguration',
            'Using Components with Known Vulnerabilities': 'A06:2021 - Vulnerable and Outdated Components',
            'Insufficient Logging': 'A09:2021 - Logging and Monitoring Failures',
            'SSRF': 'A10:2021 - Server-Side Request Forgery'
        }
        
        found_issues = {}
        compliance_score = 100
        
        for vuln in vulnerabilities:
            for key, owasp_control in owasp_mapping.items():
                if key.lower() in vuln.lower():
                    found_issues[owasp_control] = found_issues.get(owasp_control, 0) + 1
                    compliance_score -= 10
        
        return {
            'framework': 'OWASP Top 10',
            'found_issues': found_issues,
            'compliance_score': max(0, compliance_score),
            'status': 'Compliant' if compliance_score >= 80 else 'Non-Compliant',
            'recommendations': self._get_owasp_recommendations(found_issues)
        }
    
    def assess_nist_compliance(self, security_controls: Dict) -> Dict:
        """Assess compliance against NIST framework"""
        nist_categories = self.compliance_frameworks['NIST']['controls']
        
        implemented_controls = []
        missing_controls = []
        
        for control in nist_categories:
            if any(control.lower() in str(v).lower() for v in security_controls.values()):
                implemented_controls.append(control)
            else:
                missing_controls.append(control)
        
        compliance_percentage = (len(implemented_controls) / len(nist_categories)) * 100
        
        return {
            'framework': 'NIST Cybersecurity Framework',
            'implemented_controls': implemented_controls,
            'missing_controls': missing_controls,
            'compliance_percentage': round(compliance_percentage, 2),
            'status': 'Compliant' if compliance_percentage >= 80 else 'Partially Compliant',
            'action_items': missing_controls
        }
    
    def assess_iso27001_compliance(self, security_measures: List[str]) -> Dict:
        """Assess compliance against ISO 27001"""
        iso_controls = self.compliance_frameworks['ISO27001']['controls']
        
        implemented = []
        not_implemented = []
        
        for control in iso_controls:
            if any(control.lower() in str(m).lower() for m in security_measures):
                implemented.append(control)
            else:
                not_implemented.append(control)
        
        compliance_score = (len(implemented) / len(iso_controls)) * 100
        
        return {
            'framework': 'ISO/IEC 27001',
            'implemented_controls': len(implemented),
            'total_controls': len(iso_controls),
            'compliance_score': round(compliance_score, 2),
            'status': 'Certified Ready' if compliance_score >= 95 else 'Review Needed',
            'gap_analysis': not_implemented[:5]  # Top 5 gaps
        }
    
    def assess_pci_dss_compliance(self, findings: Dict) -> Dict:
        """Assess compliance against PCI DSS"""
        pci_requirements = self.compliance_frameworks['PCI-DSS']['controls']
        
        compliant_requirements = []
        non_compliant_requirements = []
        
        for req in pci_requirements:
            # Simplified assessment logic
            req_num = req.split(':')[0]
            if findings.get(req_num, {}).get('compliant', False):
                compliant_requirements.append(req)
            else:
                non_compliant_requirements.append(req)
        
        compliance_percentage = (len(compliant_requirements) / len(pci_requirements)) * 100
        
        return {
            'framework': 'PCI DSS',
            'compliant_requirements': len(compliant_requirements),
            'non_compliant_requirements': len(non_compliant_requirements),
            'total_requirements': len(pci_requirements),
            'compliance_percentage': round(compliance_percentage, 2),
            'status': 'Compliant' if compliance_percentage >= 100 else 'Non-Compliant',
            'critical_findings': non_compliant_requirements
        }
    
    def generate_compliance_report(self, assessments: Dict) -> str:
        """Generate comprehensive GRC compliance report"""
        report = "=" * 70 + "\n"
        report += "GRC COMPLIANCE ASSESSMENT REPORT\n"
        report += "=" * 70 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        total_score = 0
        framework_count = 0
        
        for framework, assessment in assessments.items():
            if 'compliance_score' in assessment:
                total_score += assessment['compliance_score']
                framework_count += 1
            elif 'compliance_percentage' in assessment:
                total_score += assessment['compliance_percentage']
                framework_count += 1
            
            report += f"\n{'=' * 70}\n"
            report += f"{assessment.get('framework', framework).upper()}\n"
            report += f"{'=' * 70}\n"
            report += f"Status: {assessment.get('status', 'Unknown')}\n"
            
            if 'compliance_score' in assessment:
                report += f"Score: {assessment['compliance_score']}/100\n"
            elif 'compliance_percentage' in assessment:
                report += f"Compliance: {assessment['compliance_percentage']}%\n"
        
        if framework_count > 0:
            avg_score = total_score / framework_count
            report += f"\n\nOVERALL COMPLIANCE SCORE: {round(avg_score, 2)}/100\n"
        
        return report
    
    def _get_owasp_recommendations(self, issues: Dict) -> List[str]:
        """Get recommendations for OWASP issues"""
        recommendations = {
            'A01:2021 - Broken Access Control': 'Implement proper authorization checks for all resources',
            'A02:2021 - Cryptographic Failures': 'Use strong encryption for sensitive data and HTTPS for transmission',
            'A03:2021 - Injection': 'Use parameterized queries and input validation',
            'A05:2021 - Security Misconfiguration': 'Disable default accounts and unnecessary services',
            'A07:2021 - Authentication Failures': 'Implement MFA and strong password policies',
            'A09:2021 - Logging and Monitoring Failures': 'Enable comprehensive logging and real-time monitoring'
        }
        
        return [recommendations.get(issue, f'Address {issue}') for issue in issues.keys()]
