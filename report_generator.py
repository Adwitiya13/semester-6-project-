#!/usr/bin/env python3
"""
Automated Security Reports - Generate comprehensive security analysis reports
"""

from typing import Dict, List
from datetime import datetime
import json
import csv
from io import StringIO

class SecurityReportGenerator:
    """Generate automated security reports in multiple formats"""
    
    def __init__(self):
        self.report_data = {}
        self.timestamp = datetime.now()
    
    def generate_executive_summary(self, findings: Dict) -> str:
        """Generate executive summary for management"""
        summary = "=" * 80 + "\n"
        summary += "EXECUTIVE SUMMARY - SECURITY ASSESSMENT\n"
        summary += "=" * 80 + "\n"
        summary += f"Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        summary += "KEY FINDINGS\n"
        summary += "-" * 80 + "\n"
        
        if findings.get('critical_count', 0) > 0:
            summary += f"🔴 CRITICAL: {findings['critical_count']} issues require immediate attention\n"
        
        if findings.get('high_count', 0) > 0:
            summary += f"🟠 HIGH: {findings['high_count']} issues require urgent remediation\n"
        
        if findings.get('medium_count', 0) > 0:
            summary += f"🟡 MEDIUM: {findings['medium_count']} issues should be scheduled for remediation\n"
        
        if findings.get('low_count', 0) > 0:
            summary += f"🟢 LOW: {findings['low_count']} issues for monitoring\n"
        
        summary += f"\nOVERALL RISK SCORE: {findings.get('overall_risk_score', 'N/A')}/10\n"
        summary += f"COMPLIANCE STATUS: {findings.get('compliance_status', 'Unknown')}\n\n"
        
        summary += "RECOMMENDATIONS\n"
        summary += "-" * 80 + "\n"
        
        for i, rec in enumerate(findings.get('top_recommendations', [])[:5], 1):
            summary += f"{i}. {rec}\n"
        
        return summary
    
    def generate_detailed_report(self, assessment_data: Dict) -> str:
        """Generate detailed technical report"""
        report = "=" * 80 + "\n"
        report += "DETAILED SECURITY ASSESSMENT REPORT\n"
        report += "=" * 80 + "\n"
        report += f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Assessment Type: {assessment_data.get('type', 'Web Application Security Assessment')}\n"
        report += f"Target: {assessment_data.get('target', 'N/A')}\n\n"
        
        # Vulnerability Details
        report += "VULNERABILITY INVENTORY\n"
        report += "-" * 80 + "\n"
        
        for vuln in assessment_data.get('vulnerabilities', []):
            report += f"\n[ID: {vuln.get('id', 'N/A')}]\n"
            report += f"Title: {vuln.get('title', 'N/A')}\n"
            report += f"Severity: {vuln.get('severity', 'N/A')}\n"
            report += f"Description: {vuln.get('description', 'N/A')}\n"
            report += f"Affected Component: {vuln.get('affected_component', 'N/A')}\n"
            report += f"Remediation: {vuln.get('remediation', 'N/A')}\n"
            report += f"References: {vuln.get('references', 'N/A')}\n"
        
        # Compliance Status
        report += f"\n\nCOMPLIANCE ASSESSMENT\n"
        report += "-" * 80 + "\n"
        
        for framework, status in assessment_data.get('compliance', {}).items():
            report += f"{framework}: {status}\n"
        
        return report
    
    def generate_html_report(self, findings: Dict, filename: str = None) -> str:
        """Generate HTML report for web viewing"""
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        
        header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding: 30px 0;
            margin-bottom: 30px;
        }
        
        h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .summary-box {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .metric-card.critical {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .metric-card.high {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }
        
        .metric-card.medium {
            background: linear-gradient(135deg, #30cfd0 0%, #330867 100%);
        }
        
        .metric-number {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .metric-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .risk-score {
            font-size: 3em;
            font-weight: bold;
            color: #f5576c;
            text-align: center;
            margin: 30px 0;
        }
        
        h2 {
            color: #2c3e50;
            border-left: 4px solid #667eea;
            padding-left: 15px;
            margin: 30px 0 15px 0;
        }
        
        h3 {
            color: #34495e;
            margin: 20px 0 10px 0;
        }
        
        ul, ol {
            margin-left: 20px;
            margin-bottom: 15px;
        }
        
        li {
            margin-bottom: 8px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        
        th {
            background-color: #2c3e50;
            color: white;
        }
        
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        .severity-critical {
            color: #f5576c;
            font-weight: bold;
        }
        
        .severity-high {
            color: #fa709a;
            font-weight: bold;
        }
        
        .severity-medium {
            color: #f5d76e;
            font-weight: bold;
        }
        
        .severity-low {
            color: #2ecc71;
            font-weight: bold;
        }
        
        .recommendations {
            background-color: #ecf0f1;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        
        .recommendation-item {
            margin: 10px 0;
            padding: 10px;
            background-color: white;
            border-radius: 4px;
        }
        
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .status-indicator {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .compliant {
            background-color: #2ecc71;
        }
        
        .non-compliant {
            background-color: #e74c3c;
        }
        
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <p class="timestamp">Generated: """ + self.timestamp.strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </header>
        
        <section class="summary-section">
            <h2>Assessment Summary</h2>
            <div class="summary-box">
                <div class="metric-card critical">
                    <div class="metric-label">Critical Issues</div>
                    <div class="metric-number">""" + str(findings.get('critical_count', 0)) + """</div>
                </div>
                <div class="metric-card high">
                    <div class="metric-label">High Risk Issues</div>
                    <div class="metric-number">""" + str(findings.get('high_count', 0)) + """</div>
                </div>
                <div class="metric-card medium">
                    <div class="metric-label">Medium Issues</div>
                    <div class="metric-number">""" + str(findings.get('medium_count', 0)) + """</div>
                </div>
            </div>
            
            <div class="risk-score">
                Risk Score: """ + str(findings.get('overall_risk_score', 'N/A')) + """/10
            </div>
            
            <h3>Compliance Status</h3>
            <p>""" + str(findings.get('compliance_status', 'Unknown')) + """</p>
        </section>
        
        <section class="recommendations-section">
            <h2>Top Recommendations</h2>
            <div class="recommendations">
        """
        
        for i, rec in enumerate(findings.get('top_recommendations', [])[:5], 1):
            html += f'<div class="recommendation-item"><strong>{i}.</strong> {rec}</div>'
        
        html += """
            </div>
        </section>
        
        <footer>
            <p>This report contains confidential security assessment information.</p>
            <p>© 2024 Website Vulnerability Analyzer. All rights reserved.</p>
        </footer>
    </div>
</body>
</html>
        """
        
        if filename:
            with open(filename, 'w') as f:
                f.write(html)
        
        return html
    
    def generate_csv_report(self, vulnerabilities: List[Dict], filename: str = None) -> str:
        """Generate CSV format report"""
        output = StringIO()
        writer = csv.writer(output)
        
        # Header row
        writer.writerow(['ID', 'Title', 'Severity', 'Description', 'Affected Component', 'Remediation'])
        
        # Data rows
        for vuln in vulnerabilities:
            writer.writerow([
                vuln.get('id', 'N/A'),
                vuln.get('title', 'N/A'),
                vuln.get('severity', 'N/A'),
                vuln.get('description', 'N/A'),
                vuln.get('affected_component', 'N/A'),
                vuln.get('remediation', 'N/A')
            ])
        
        csv_string = output.getvalue()
        
        if filename:
            with open(filename, 'w', newline='') as f:
                f.write(csv_string)
        
        return csv_string
    
    def generate_json_report(self, assessment_data: Dict, filename: str = None) -> str:
        """Generate JSON format report"""
        report_dict = {
            'timestamp': self.timestamp.isoformat(),
            'assessment_data': assessment_data,
            'metadata': {
                'report_version': '1.0',
                'generator': 'Website Vulnerability Analyzer'
            }
        }
        
        json_string = json.dumps(report_dict, indent=2)
        
        if filename:
            with open(filename, 'w') as f:
                f.write(json_string)
        
        return json_string
    
    def generate_compliance_report(self, compliance_data: Dict) -> str:
        """Generate compliance assessment report"""
        report = "=" * 80 + "\n"
        report += "COMPLIANCE ASSESSMENT REPORT\n"
        report += "=" * 80 + "\n"
        report += f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        for framework, data in compliance_data.items():
            report += f"\n{framework}\n"
            report += "-" * 80 + "\n"
            report += f"Status: {data.get('status', 'Unknown')}\n"
            report += f"Score: {data.get('score', 'N/A')}%\n"
            
            if 'gaps' in data:
                report += f"\nCompliance Gaps:\n"
                for gap in data['gaps'][:5]:
                    report += f"  • {gap}\n"
        
        return report
