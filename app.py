#!/usr/bin/env python3
"""
Website Vulnerability Analyzer - Web Interface
Flask-based web application for security analysis
"""

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import io

# Import security modules
from crypto_toolkit import RSA, DSA
from password_analyzer import PasswordAnalyzer
from network_scanner import NetworkSecurityScanner
from file_analyzer import FileSecurityAnalyzer
from grc_engine import GRCComplianceEngine
from risk_scorer import RiskScoringSystem
from report_generator import SecurityReportGenerator
from otp_sharing import OTPManager, SecureReportSharing

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Add CORS headers manually
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize security modules
password_analyzer = PasswordAnalyzer()
network_scanner = NetworkSecurityScanner()
file_analyzer = FileSecurityAnalyzer()
grc_engine = GRCComplianceEngine()
risk_scorer = RiskScoringSystem()
report_generator = SecurityReportGenerator()
otp_manager = OTPManager()
report_sharer = SecureReportSharing()


@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/demo')
def demo():
    """Demo page"""
    return render_template('demo.html')


@app.route('/analyzer')
def analyzer():
    """Website analyzer page"""
    return render_template('analyzer.html')


@app.route('/password')
def password():
    """Password analyzer page"""
    return render_template('password.html')


@app.route('/crypto')
def crypto():
    """Cryptography page"""
    return render_template('crypto.html')


@app.route('/file')
def file_page():
    """File analyzer page"""
    return render_template('file.html')


@app.route('/risk')
def risk():
    """Risk assessment page"""
    return render_template('risk.html')


@app.route('/compliance')
def compliance():
    """Compliance page"""
    return render_template('compliance.html')


@app.route('/reports')
def reports():
    """Reports page"""
    return render_template('reports.html')


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/demo', methods=['POST'])
def api_demo():
    """Run comprehensive demo analysis"""
    try:
        results = {
            'rsa': run_rsa_demo(),
            'dsa': run_dsa_demo(),
            'passwords': run_password_demo(),
            'risk': run_risk_demo(),
            'timestamp': datetime.now().isoformat()
        }
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


def run_rsa_demo():
    """Run RSA encryption demo"""
    rsa = RSA(key_size=2048)
    message = 123456789
    ciphertext = rsa.encrypt(message)
    decrypted = rsa.decrypt(ciphertext)
    
    return {
        'algorithm': 'RSA',
        'key_size': 2048,
        'message': message,
        'encrypted': str(ciphertext)[:100] + '...',
        'decrypted': decrypted,
        'success': decrypted == message,
        'status': 'Strong'
    }


def run_dsa_demo():
    """Run DSA signature demo"""
    dsa = DSA(key_size=1024)
    message = "Security Document"
    r, s = dsa.sign(message)
    is_valid = dsa.verify(message, (r, s))
    
    return {
        'algorithm': 'DSA',
        'key_size': 1024,
        'message': message,
        'signature_valid': is_valid,
        'tamper_detection': not dsa.verify(message + " TAMPERED", (r, s)),
        'hash': 'SHA-256',
        'status': 'Strong'
    }


def run_password_demo():
    """Run password strength demo"""
    passwords = [
        'password123',
        'Str0ng!Pass#2024',
        'MyP@ssw0rd',
        'Weak'
    ]
    
    results = []
    for pwd in passwords:
        analysis = password_analyzer.analyze_password(pwd)
        results.append({
            'password': '****' if len(pwd) > 4 else pwd,
            'strength': analysis['strength_level'],
            'score': analysis['strength_score'],
            'entropy': analysis['entropy_bits'],
            'crack_time': analysis['crack_time_estimate']
        })
    
    return results


def run_risk_demo():
    """Run risk assessment demo"""
    vulnerabilities = [
        {
            'name': 'Missing HTTPS',
            'ease_of_exploitation': 0.8,
            'prevalence': 0.9,
            'confidentiality_impact': 0.8,
            'integrity_impact': 0.7,
            'availability_impact': 0.5
        }
    ]
    
    portfolio = risk_scorer.calculate_portfolio_risk(vulnerabilities)
    return {
        'total_vulnerabilities': portfolio['total_vulnerabilities'],
        'risk_score': portfolio['portfolio_risk_score'],
        'severity': portfolio['portfolio_severity'],
        'recommendations': portfolio['remediation_priority']
    }


@app.route('/api/analyze-website', methods=['POST'])
def api_analyze_website():
    """Analyze website for vulnerabilities"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'status': 'error', 'message': 'URL required'}), 400
        
        # Validate URL
        import validators
        if not validators.url(url):
            return jsonify({'status': 'error', 'message': 'Invalid URL format'}), 400
        
        # Analyze
        import requests
        from bs4 import BeautifulSoup, Comment
        from urllib.parse import urlparse
        
        response = requests.get(url, timeout=10)
        html = response.text
        
        # SSL/TLS check
        ssl_result = network_scanner.check_ssl_tls(url)
        
        # Security headers
        headers_result = network_scanner.check_headers(dict(response.headers))
        
        # XSS check
        xss_result = network_scanner.check_xss_vulnerabilities(html)
        
        # Parse HTML
        parsed_html = BeautifulSoup(html, 'html.parser')
        forms = len(parsed_html.find_all('form'))
        comments = len(parsed_html.find_all(string=lambda text: isinstance(text, Comment)))
        
        results = {
            'url': url,
            'ssl_tls': ssl_result,
            'security_headers': {
                'score': headers_result['security_score'],
                'missing': len(headers_result['missing_headers'])
            },
            'xss_vulnerabilities': xss_result['total_vulnerabilities'],
            'forms_found': forms,
            'comments_found': comments,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/analyze-password', methods=['POST'])
def api_analyze_password():
    """Analyze password strength"""
    try:
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({'status': 'error', 'message': 'Password required'}), 400
        
        analysis = password_analyzer.analyze_password(password)
        
        results = {
            'length': analysis['password_length'],
            'strength': analysis['strength_level'],
            'score': analysis['strength_score'],
            'entropy': analysis['entropy_bits'],
            'crack_time': analysis['crack_time_estimate'],
            'has_uppercase': analysis['character_patterns']['has_uppercase'],
            'has_lowercase': analysis['character_patterns']['has_lowercase'],
            'has_digits': analysis['character_patterns']['has_digits'],
            'has_special': analysis['character_patterns']['has_special'],
            'is_common': analysis['is_common_password'],
            'recommendations': analysis['recommendations']
        }
        
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/generate-password', methods=['POST'])
def api_generate_password():
    """Generate strong password"""
    try:
        data = request.get_json()
        length = data.get('length', 16)
        
        password = password_analyzer.generate_strong_password(length)
        analysis = password_analyzer.analyze_password(password)
        
        return jsonify({
            'status': 'success',
            'data': {
                'password': password,
                'strength': analysis['strength_level'],
                'score': analysis['strength_score'],
                'entropy': analysis['entropy_bits']
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/rsa-encrypt', methods=['POST'])
def api_rsa_encrypt():
    """RSA encryption demo"""
    try:
        data = request.get_json()
        message = int(data.get('message', 123456789))
        
        rsa = RSA(key_size=2048)
        ciphertext = rsa.encrypt(message)
        decrypted = rsa.decrypt(ciphertext)
        
        return jsonify({
            'status': 'success',
            'data': {
                'algorithm': 'RSA',
                'key_size': 2048,
                'message': message,
                'encrypted': str(ciphertext),
                'decrypted': decrypted,
                'success': decrypted == message,
                'public_key': str(rsa.public_key),
                'status': 'Strong'
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/dsa-sign', methods=['POST'])
def api_dsa_sign():
    """DSA signature demo"""
    try:
        data = request.get_json()
        message = data.get('message', 'Security Document')
        
        dsa = DSA(key_size=1024)
        r, s = dsa.sign(message)
        is_valid = dsa.verify(message, (r, s))
        is_tampered = dsa.verify(message + " TAMPERED", (r, s))
        
        return jsonify({
            'status': 'success',
            'data': {
                'algorithm': 'DSA',
                'key_size': 1024,
                'message': message,
                'signature_r': str(r),
                'signature_s': str(s),
                'signature_valid': is_valid,
                'tamper_detection': not is_tampered,
                'hash': 'SHA-256',
                'status': 'Strong'
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/analyze-file', methods=['POST'])
def api_analyze_file():
    """Analyze uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze file
        permissions = file_analyzer.check_file_permissions(filepath)
        extension = file_analyzer.check_file_extension_safety(filepath)
        file_hash = file_analyzer.calculate_file_hash(filepath)
        
        results = {
            'filename': filename,
            'permissions': permissions.get('permissions', 'N/A'),
            'is_dangerous': extension.get('is_dangerous', False),
            'extension': extension.get('extension', 'N/A'),
            'hash_sha256': file_hash.get('hash', 'N/A')[:32] + '...',
            'status': permissions.get('status', 'Unknown')
        }
        
        # Cleanup
        if os.path.exists(filepath):
            os.remove(filepath)
        
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/risk-assessment', methods=['POST'])
def api_risk_assessment():
    """Perform risk assessment"""
    try:
        data = request.get_json()
        vulnerabilities = data.get('vulnerabilities', [
            {
                'name': 'Missing HTTPS',
                'ease_of_exploitation': 0.8,
                'prevalence': 0.9,
                'confidentiality_impact': 0.8,
                'integrity_impact': 0.7,
                'availability_impact': 0.5
            }
        ])
        
        portfolio = risk_scorer.calculate_portfolio_risk(vulnerabilities)
        
        results = {
            'total_vulnerabilities': portfolio['total_vulnerabilities'],
            'risk_score': portfolio['portfolio_risk_score'],
            'severity': portfolio['portfolio_severity'],
            'severity_breakdown': portfolio['severity_distribution'],
            'recommendations': portfolio['remediation_priority']
        }
        
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/compliance-assessment', methods=['POST'])
def api_compliance_assessment():
    """Assess compliance"""
    try:
        vulnerabilities = [
            'Missing HTTPS',
            'SQL Injection risk',
            'XSS vulnerability'
        ]
        
        assessment = grc_engine.assess_owasp_compliance(vulnerabilities)
        
        return jsonify({
            'status': 'success',
            'data': {
                'framework': assessment['framework'],
                'score': assessment['compliance_score'],
                'status': assessment['status'],
                'issues_found': list(assessment['found_issues'].keys()),
                'recommendations': assessment['recommendations']
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/generate-otp', methods=['POST'])
def api_generate_otp():
    """Generate OTP for report sharing"""
    try:
        data = request.get_json()
        email = data.get('email', 'user@example.com')
        
        otp_result = otp_manager.generate_email_otp(validity_minutes=15)
        
        return jsonify({
            'status': 'success',
            'data': {
                'otp': otp_result['otp'],
                'validity_minutes': otp_result['validity_minutes'],
                'format': otp_result['format']
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check"""
    return jsonify({
        'status': 'success',
        'message': 'Security Analyzer API is running',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    })


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'status': 'error', 'message': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({'status': 'error', 'message': 'Server error'}), 500


if __name__ == '__main__':
    print("\n" + "="*70)
    print("WEBSITE VULNERABILITY ANALYZER - WEB VERSION")
    print("="*70)
    print("\n[*] Starting Flask application...")
    print("[*] Access the application at: http://localhost:5000")
    print("[*] Press Ctrl+C to stop the server")
    print("\n" + "="*70 + "\n")
    
    app.run(debug=True, host='localhost', port=5000)
