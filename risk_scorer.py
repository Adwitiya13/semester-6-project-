#!/usr/bin/env python3
"""
Risk Scoring System - Quantify and prioritize security risks
"""

from typing import Dict, List, Tuple
from datetime import datetime

class RiskScoringSystem:
    """Comprehensive risk assessment and scoring"""
    
    def __init__(self):
        self.risk_matrix = {
            'Critical': {'score': 9.0, 'color': '🔴', 'action': 'Immediate remediation required'},
            'High': {'score': 7.0, 'color': '🟠', 'action': 'Urgent remediation needed'},
            'Medium': {'score': 5.0, 'color': '🟡', 'action': 'Schedule remediation'},
            'Low': {'score': 3.0, 'color': '🟢', 'action': 'Monitor and plan remediation'},
            'Informational': {'score': 1.0, 'color': '⚪', 'action': 'For information only'}
        }
    
    def calculate_cvss_v3_score(self, metrics: Dict) -> Dict:
        """
        Calculate CVSS v3.1 score
        metrics = {
            'AV': 'N|A|L|P',  # Attack Vector
            'AT': 'N|L',      # Attack Complexity
            'PR': 'N|L|H',    # Privileges Required
            'UI': 'N|R',      # User Interaction
            'S': 'U|C',       # Scope
            'C': 'H|L|N',     # Confidentiality
            'I': 'H|L|N',     # Integrity
            'A': 'H|L|N'      # Availability
        }
        """
        
        # Base score calculation
        av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        at_scores = {'N': 0.77, 'L': 0.62}
        pr_scores = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        ui_scores = {'N': 0.85, 'R': 0.62}
        s_scores = {'U': 0.85, 'C': 1.08}
        c_scores = {'H': 0.56, 'L': 0.22, 'N': 0.0}
        i_scores = {'H': 0.56, 'L': 0.22, 'N': 0.0}
        a_scores = {'H': 0.56, 'L': 0.22, 'N': 0.0}
        
        # Calculate base score
        av = av_scores.get(metrics.get('AV', 'N'), 0.85)
        at = at_scores.get(metrics.get('AT', 'N'), 0.77)
        pr = pr_scores.get(metrics.get('PR', 'N'), 0.85)
        ui = ui_scores.get(metrics.get('UI', 'N'), 0.85)
        s = s_scores.get(metrics.get('S', 'U'), 0.85)
        
        c = c_scores.get(metrics.get('C', 'N'), 0.0)
        i = i_scores.get(metrics.get('I', 'N'), 0.0)
        a = a_scores.get(metrics.get('A', 'N'), 0.0)
        
        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        base_score = min(3.1 * isc_base * av * at * pr * ui, 10.0)
        
        # Determine severity rating
        if base_score >= 9.0:
            severity = 'Critical'
        elif base_score >= 7.0:
            severity = 'High'
        elif base_score >= 4.0:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        return {
            'cvss_score': round(base_score, 1),
            'severity': severity,
            'vector_string': f"CVSS:3.1/AV:{metrics.get('AV', 'N')}/AT:{metrics.get('AT', 'N')}/PR:{metrics.get('PR', 'N')}/UI:{metrics.get('UI', 'N')}/S:{metrics.get('S', 'U')}/C:{metrics.get('C', 'H')}/I:{metrics.get('I', 'H')}/A:{metrics.get('A', 'H')}",
            'action_required': self.risk_matrix.get(severity, {}).get('action', 'Review needed')
        }
    
    def calculate_risk_score(self, vulnerability: Dict) -> Dict:
        """Calculate overall risk score for a vulnerability"""
        
        # Likelihood factors (0-1.0)
        likelihood = 0.5
        
        # Ease of Exploitation (0-1.0)
        ease = vulnerability.get('ease_of_exploitation', 0.7)
        likelihood *= ease
        
        # Prevalence (0-1.0)
        prevalence = vulnerability.get('prevalence', 0.8)
        likelihood *= prevalence
        
        # Impact factors (0-1.0)
        impact = 0.5
        
        # Confidentiality Impact
        confidentality_impact = vulnerability.get('confidentiality_impact', 0.7)
        impact *= confidentality_impact
        
        # Integrity Impact
        integrity_impact = vulnerability.get('integrity_impact', 0.7)
        impact *= integrity_impact
        
        # Availability Impact
        availability_impact = vulnerability.get('availability_impact', 0.7)
        impact *= availability_impact
        
        # Overall Risk Score
        risk_score = (likelihood + impact) / 2 * 10
        
        # Determine severity
        if risk_score >= 8.5:
            severity = 'Critical'
        elif risk_score >= 6.0:
            severity = 'High'
        elif risk_score >= 4.0:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        return {
            'vulnerability': vulnerability.get('name', 'Unknown'),
            'risk_score': round(risk_score, 2),
            'severity': severity,
            'likelihood_factors': {
                'ease_of_exploitation': ease,
                'prevalence': prevalence
            },
            'impact_factors': {
                'confidentiality': confidentality_impact,
                'integrity': integrity_impact,
                'availability': availability_impact
            },
            'color_indicator': self.risk_matrix.get(severity, {}).get('color', '⚪'),
            'action': self.risk_matrix.get(severity, {}).get('action', 'Review')
        }
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Prioritize vulnerabilities by risk score"""
        scored_vulns = []
        
        for vuln in vulnerabilities:
            risk = self.calculate_risk_score(vuln)
            scored_vulns.append(risk)
        
        # Sort by risk score (descending)
        scored_vulns.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return scored_vulns
    
    def calculate_portfolio_risk(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate overall portfolio risk"""
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'portfolio_risk_score': 0,
                'severity_distribution': {},
                'status': 'No vulnerabilities detected'
            }
        
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        
        total_risk = 0
        
        for vuln in vulnerabilities:
            risk = self.calculate_risk_score(vuln)
            total_risk += risk['risk_score']
            severity_counts[risk['severity']] += 1
        
        avg_risk = total_risk / len(vulnerabilities)
        
        # Determine portfolio severity
        if severity_counts['Critical'] > 0:
            portfolio_severity = 'Critical'
        elif severity_counts['High'] > 2:
            portfolio_severity = 'High'
        elif severity_counts['Medium'] > 5:
            portfolio_severity = 'Medium'
        else:
            portfolio_severity = 'Low'
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'portfolio_risk_score': round(avg_risk, 2),
            'portfolio_severity': portfolio_severity,
            'severity_distribution': severity_counts,
            'remediation_priority': self._get_remediation_plan(vulnerability_counts=severity_counts)
        }
    
    def _get_remediation_plan(self, vulnerability_counts: Dict) -> List[str]:
        """Generate remediation plan based on vulnerability counts"""
        plan = []
        
        if vulnerability_counts.get('Critical', 0) > 0:
            plan.append(f"IMMEDIATE: Fix {vulnerability_counts['Critical']} critical vulnerabilities")
        
        if vulnerability_counts.get('High', 0) > 0:
            plan.append(f"URGENT: Fix {vulnerability_counts['High']} high-risk vulnerabilities within 7 days")
        
        if vulnerability_counts.get('Medium', 0) > 0:
            plan.append(f"SCHEDULE: Fix {vulnerability_counts['Medium']} medium-risk vulnerabilities within 30 days")
        
        if vulnerability_counts.get('Low', 0) > 0:
            plan.append(f"MONITOR: Review {vulnerability_counts['Low']} low-risk vulnerabilities within 90 days")
        
        return plan
    
    def generate_risk_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate risk assessment report"""
        report = "=" * 70 + "\n"
        report += "RISK ASSESSMENT REPORT\n"
        report += "=" * 70 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        portfolio = self.calculate_portfolio_risk(vulnerabilities)
        
        report += f"PORTFOLIO SUMMARY\n"
        report += f"  Total Vulnerabilities: {portfolio['total_vulnerabilities']}\n"
        report += f"  Average Risk Score: {portfolio['portfolio_risk_score']}/10\n"
        report += f"  Portfolio Severity: {portfolio['portfolio_severity']}\n\n"
        
        report += f"SEVERITY DISTRIBUTION\n"
        for severity, count in portfolio['severity_distribution'].items():
            if count > 0:
                report += f"  {self.risk_matrix[severity]['color']} {severity}: {count}\n"
        
        report += f"\nREMEDIATION PLAN\n"
        for action in portfolio['remediation_priority']:
            report += f"  • {action}\n"
        
        report += f"\nVULNERABILITY PRIORITY LIST\n"
        prioritized = self.prioritize_vulnerabilities(vulnerabilities)
        for i, vuln in enumerate(prioritized[:10], 1):
            report += f"  {i}. {vuln['color_indicator']} {vuln['vulnerability']} "
            report += f"(Risk: {vuln['risk_score']}/10) - {vuln['action']}\n"
        
        return report
    
    def export_risk_metrics(self, vulnerabilities: List[Dict]) -> Dict:
        """Export risk metrics for external systems"""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'portfolio_metrics': self.calculate_portfolio_risk(vulnerabilities),
            'detailed_risks': [self.calculate_risk_score(v) for v in vulnerabilities],
            'summary_score': round(sum(self.calculate_risk_score(v)['risk_score'] for v in vulnerabilities) / max(len(vulnerabilities), 1), 2)
        }
