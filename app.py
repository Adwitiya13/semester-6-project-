#!/usr/bin/env python3
"""
Website Vulnerability Analyzer - Web Interface
Flask-based web application for security analysis
"""

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import ipaddress
import os
import json
import tempfile
from datetime import datetime
import io
from pathlib import Path
from urllib.parse import urlparse

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
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.environ.get('UPLOAD_FOLDER', Path(tempfile.gettempdir()) / 'security-analyzer-uploads'))

app = Flask(__name__, template_folder=str(BASE_DIR / 'templates'))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)

# Add CORS headers manually
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Create a writable upload directory.
# Serverless platforms such as Vercel only allow writes in temp storage.
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Initialize security modules
password_analyzer = PasswordAnalyzer()
network_scanner = NetworkSecurityScanner()
file_analyzer = FileSecurityAnalyzer()
grc_engine = GRCComplianceEngine()
risk_scorer = RiskScoringSystem()
report_generator = SecurityReportGenerator()
otp_manager = OTPManager()
report_sharer = SecureReportSharing()


def api_error(message, status=400):
    """Return a standard JSON error response."""
    return jsonify({'status': 'error', 'message': message}), status


def is_public_http_url(url):
    """Validate that a URL is a usable public HTTP(S) target."""
    if not url:
        return False, 'URL required'

    parsed = urlparse(url.strip())
    if parsed.scheme not in ('http', 'https'):
        return False, 'URL must begin with http:// or https://'

    hostname = (parsed.hostname or '').lower()
    if not hostname:
        return False, 'URL host is required'

    blocked_hosts = {
        'localhost',
        '127.0.0.1',
        '::1',
    }
    if hostname in blocked_hosts or hostname.endswith('.local'):
        return False, 'Local and private hostnames are not allowed'

    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, 'Private or reserved IP addresses are not allowed'
    except ValueError:
        # Hostname is not a literal IP, which is acceptable here.
        pass

    return True, None


def build_demo_website_result():
    """Create a deterministic website security sample for the dashboard/report preview."""
    sample_headers = {
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
    }

    return {
        'url': 'https://demo.security-analyzer.local',
        'title': 'Security Analyzer Demo Site',
        'ssl_tls': {
            'protocol': 'HTTPS',
            'is_https': True,
            'status': '✔ Secure',
            'issue': None,
            'recommendation': None,
        },
        'security_headers': {
            'score': 100.0,
            'missing': 0,
            'missing_headers': [],
            'present_headers': list(sample_headers.keys()),
        },
        'xss_vulnerabilities': 0,
        'forms_found': 1,
        'comments_found': 1,
        'timestamp': datetime.now().isoformat(),
    }


def build_compliance_items(assessment_type, url, headers, html, ssl_result, xss_result):
    """Build a lightweight compliance checklist that the frontend can render directly."""
    headers_lower = {key.lower(): value for key, value in headers.items()}
    html_lower = (html or '').lower()
    assessment_type = (assessment_type or 'owasp').lower()
    items = {}

    def header_present(header_name):
        return header_name.lower() in headers_lower

    def add_item(name, passed, detail_pass, detail_fail):
        items[name] = {
            'status': 'PASS' if passed else 'FAIL',
            'details': detail_pass if passed else detail_fail,
        }

    if assessment_type == 'gdpr':
        add_item(
            'Privacy Notice',
            any(term in html_lower for term in ['privacy', 'privacy policy']),
            'Privacy notice references were detected.',
            'No privacy notice reference was found in the page content.',
        )
        add_item(
            'Cookie Consent',
            any(term in html_lower for term in ['cookie', 'consent']),
            'Cookie or consent language was detected.',
            'No cookie consent language was found.',
        )
        add_item(
            'Security Transmission',
            ssl_result.get('is_https', False),
            'HTTPS is enabled for data transmission.',
            'The page is not served over HTTPS.',
        )
        add_item(
            'Minimized Exposure',
            xss_result.get('total_vulnerabilities', 0) == 0,
            'No obvious script injection patterns were found.',
            'Potential script injection patterns were detected.',
        )
    elif assessment_type == 'pci':
        add_item(
            'HTTPS Transport',
            ssl_result.get('is_https', False),
            'HTTPS is enabled.',
            'HTTPS is missing.',
        )
        add_item(
            'Security Headers',
            all(header_present(h) for h in ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options']),
            'Core browser security headers are present.',
            'One or more browser security headers are missing.',
        )
        add_item(
            'Sensitive Payment Data',
            not any(term in html_lower for term in ['card number', 'cvv', 'cc-number', 'credit card']),
            'No obvious cardholder data was found in the page source.',
            'Potential payment card data exposure was detected.',
        )
        add_item(
            'Payment Form Protection',
            'payment' not in html_lower or header_present('Content-Security-Policy'),
            'Payment-related content appears protected.',
            'Payment-related content was found without strong browser protections.',
        )
    elif assessment_type == 'hipaa':
        add_item(
            'HTTPS Transport',
            ssl_result.get('is_https', False),
            'HTTPS is enabled.',
            'HTTPS is missing.',
        )
        add_item(
            'Sensitive Data Handling',
            not any(term in html_lower for term in ['patient', 'medical record', 'diagnosis']),
            'No obvious PHI keywords were found in page content.',
            'Potential PHI keywords were detected in page content.',
        )
        add_item(
            'Security Headers',
            any(header_present(h) for h in ['Content-Security-Policy', 'X-Frame-Options']),
            'At least one important browser security header is present.',
            'No major browser security headers were found.',
        )
        add_item(
            'Access Control Signals',
            any(term in html_lower for term in ['login', 'sign in', 'auth']),
            'Access control or authentication signals were detected.',
            'No visible access-control signals were detected.',
        )
    else:
        add_item(
            'HTTPS Transport',
            ssl_result.get('is_https', False),
            'The site is served over HTTPS.',
            'The site is not served over HTTPS.',
        )
        add_item(
            'Content Security Policy',
            header_present('Content-Security-Policy'),
            'A Content Security Policy header is present.',
            'A Content Security Policy header is missing.',
        )
        add_item(
            'Frame Protection',
            header_present('X-Frame-Options'),
            'Frame-busting protection is present.',
            'Frame-busting protection is missing.',
        )
        add_item(
            'XSS Exposure',
            xss_result.get('total_vulnerabilities', 0) == 0,
            'No obvious XSS patterns were found.',
            'Potential XSS patterns were detected.',
        )
        add_item(
            'Form Surface',
            True if 'form' not in html_lower else ssl_result.get('is_https', False),
            'Forms appear protected by HTTPS.',
            'Forms were detected on a non-HTTPS page.',
        )

    passed = sum(1 for item in items.values() if item['status'] == 'PASS')
    total = len(items) or 1
    score = round((passed / total) * 100, 1)

    framework_names = {
        'owasp': 'OWASP Top 10',
        'gdpr': 'GDPR',
        'pci': 'PCI DSS',
        'hipaa': 'HIPAA',
    }

    return {
        'framework': framework_names.get(assessment_type, 'OWASP Top 10'),
        'score': score,
        'status': 'Compliant' if score >= 80 else 'Needs Review',
        'items': items,
        'recommendations': [
            item['details']
            for item in items.values()
            if item['status'] == 'FAIL'
        ] or ['No major issues detected in the lightweight assessment.'],
    }


def safe_fetch_url(url, timeout=10):
    """Fetch a URL but degrade gracefully when outbound access is blocked."""
    import requests

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={'User-Agent': 'Security-Analyzer/2.0'}
        )
        return response.text, dict(response.headers), None
    except Exception as exc:
        return '', {}, str(exc)


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
            'website': build_demo_website_result(),
            'risk': run_risk_demo(),
            'timestamp': datetime.now().isoformat()
        }
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return api_error(str(e))


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
        data = data or {}
        url = data.get('url', '').strip()
        
        if not url:
            return api_error('URL required')
        
        is_valid, validation_error = is_public_http_url(url)
        if not is_valid:
            return api_error(validation_error)

        import validators
        if not validators.url(url):
            return api_error('Invalid URL format')
        
        # Analyze
        from bs4 import BeautifulSoup, Comment
        
        html, response_headers, fetch_error = safe_fetch_url(url, timeout=10)

        # SSL/TLS check
        ssl_result = network_scanner.check_ssl_tls(url)

        # Security headers
        headers_result = network_scanner.check_headers(response_headers)

        # XSS check
        xss_result = network_scanner.check_xss_vulnerabilities(html)
        
        # Parse HTML
        parsed_html = BeautifulSoup(html, 'html.parser')
        forms = len(parsed_html.find_all('form'))
        comments = len(parsed_html.find_all(string=lambda text: isinstance(text, Comment)))
        
        results = {
            'url': url,
            'title': parsed_html.title.string.strip() if parsed_html.title and parsed_html.title.string else None,
            'ssl_tls': ssl_result,
            'security_headers': {
                'score': headers_result['security_score'],
                'missing': len(headers_result['missing_headers']),
                'missing_headers': headers_result['missing_headers'],
            },
            'xss_vulnerabilities': xss_result['total_vulnerabilities'],
            'forms_found': forms,
            'comments_found': comments,
            'fetch_error': fetch_error,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return api_error(str(e))


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
        return api_error(str(e))


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
        return api_error(str(e))


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
        return api_error(str(e))


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
        return api_error(str(e))


@app.route('/api/analyze-file', methods=['POST'])
def api_analyze_file():
    """Analyze uploaded file"""
    try:
        if 'file' not in request.files:
            return api_error('No file provided')
        
        file = request.files['file']
        if file.filename == '':
            return api_error('No file selected')
        
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
        return api_error(str(e))


@app.route('/api/risk-assessment', methods=['POST'])
def api_risk_assessment():
    """Perform risk assessment"""
    try:
        data = request.get_json()
        data = data or {}
        target = data.get('target', 'Unknown target').strip() or 'Unknown target'
        vulnerability = data.get('vulnerability', 'Potential security issue').strip() or 'Potential security issue'

        vulnerability_lower = vulnerability.lower()
        if any(word in vulnerability_lower for word in ['xss', 'sql injection', 'injection', 'ssrf', 'rce', 'remote code', 'auth']):
            metrics = {'AV': 'N', 'AT': 'N', 'PR': 'N', 'UI': 'R' if 'xss' in vulnerability_lower or 'csrf' in vulnerability_lower else 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'}
            likelihood = 0.9
            impact = 0.9
        elif any(word in vulnerability_lower for word in ['https', 'header', 'cookie', 'misconfiguration', 'exposure']):
            metrics = {'AV': 'N', 'AT': 'N', 'PR': 'N', 'UI': 'R', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'}
            likelihood = 0.6
            impact = 0.5
        else:
            metrics = {'AV': 'N', 'AT': 'N', 'PR': 'N', 'UI': 'R', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'L'}
            likelihood = 0.5
            impact = 0.4

        cvss = risk_scorer.calculate_cvss_v3_score(metrics)
        heuristic = risk_scorer.calculate_risk_score({
            'name': vulnerability,
            'ease_of_exploitation': likelihood,
            'prevalence': 0.8,
            'confidentiality_impact': impact,
            'integrity_impact': impact,
            'availability_impact': 0.6 if impact >= 0.6 else 0.4,
        })

        mitigation = {
            'Critical': 'Patch immediately, rotate exposed secrets, and validate the fix.',
            'High': 'Prioritize remediation within days and add compensating controls.',
            'Medium': 'Schedule remediation, add monitoring, and review the affected surface.',
            'Low': 'Track the issue, document the risk, and remediate in the next cycle.',
        }.get(heuristic['severity'], 'Document and monitor the issue.')

        results = {
            'target': target,
            'vulnerability': vulnerability,
            'cvss_score': cvss['cvss_score'],
            'severity_rating': cvss['severity'],
            'risk_level': heuristic['severity'],
            'recommendation': cvss['action_required'],
            'mitigation': mitigation,
            'vector_string': cvss['vector_string'],
            'risk_details': heuristic,
        }
        
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        return api_error(str(e))


@app.route('/api/compliance-assessment', methods=['POST'])
def api_compliance_assessment():
    """Assess compliance"""
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        assessment_type = (data.get('assessment_type') or 'owasp').lower()

        if not url:
            return api_error('URL required')

        is_valid, validation_error = is_public_http_url(url)
        if not is_valid:
            return api_error(validation_error)

        html, response_headers, fetch_error = safe_fetch_url(url, timeout=10)
        ssl_result = network_scanner.check_ssl_tls(url)
        xss_result = network_scanner.check_xss_vulnerabilities(html)
        assessment = build_compliance_items(assessment_type, url, response_headers, html, ssl_result, xss_result)
        assessment['fetch_error'] = fetch_error

        return jsonify({'status': 'success', 'data': assessment})
    except Exception as e:
        return api_error(str(e))


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
        return api_error(str(e))


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
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() in ('1', 'true', 'yes')

    print("\n" + "="*70)
    print("WEBSITE VULNERABILITY ANALYZER - WEB VERSION")
    print("="*70)
    print(f"\n[*] Starting Flask application on 0.0.0.0:{port} (debug={debug_mode})")
    print("[*] Access the application at: http://localhost:" + str(port))
    print("[*] Press Ctrl+C to stop the server")
    print("\n" + "="*70 + "\n")
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
