#!/usr/bin/env python3
"""
Simplified Flask debugging version
"""

from flask import Flask, render_template, request, jsonify
import os
import traceback

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

# Add CORS headers
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Create uploads folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ============================================================================
# ROUTE HANDLERS
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

@app.route('/analyzer')
def analyzer():
    return render_template('analyzer.html')

@app.route('/password')
def password():
    return render_template('password.html')

@app.route('/crypto')
def crypto():
    return render_template('crypto.html')

@app.route('/file')
def file():
    return render_template('file.html')

@app.route('/risk')
def risk():
    return render_template('risk.html')

@app.route('/compliance')
def compliance():
    return render_template('compliance.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

# ============================================================================
# SIMPLE API ENDPOINTS (WITHOUT MODULE DEPENDENCIES)
# ============================================================================

@app.route('/api/demo', methods=['POST', 'GET'])
def api_demo():
    """Demo endpoint - returns dummy data"""
    try:
        results = {
            'rsa': {
                'algorithm': 'RSA',
                'key_size': 2048,
                'status': 'Strong',
                'message': 123456789,
                'encrypted': 'a5f3e8d9c2...',
                'decrypted': 123456789,
                'success': True
            },
            'dsa': {
                'algorithm': 'DSA',
                'key_size': 1024,
                'status': 'Strong',
                'message': 'Security Document',
                'signature_valid': True,
                'tamper_detection': True,
                'hash': 'SHA-256'
            },
            'passwords': [
                {'password': '****', 'strength': 'Weak', 'score': 2, 'entropy': 6.9, 'crack_time': 'Instant'},
                {'password': '****', 'strength': 'Very Strong', 'score': 9, 'entropy': 48.6, 'crack_time': '1000+ Years'},
                {'password': '****', 'strength': 'Strong', 'score': 7, 'entropy': 36.1, 'crack_time': '30+ Years'},
                {'password': '****', 'strength': 'Very Weak', 'score': 1, 'entropy': 2.3, 'crack_time': 'Instant'}
            ],
            'risk': {
                'total_vulnerabilities': 1,
                'risk_score': 3.5,
                'severity': 'High',
                'recommendations': ['Enable HTTPS/TLS', 'Implement security headers']
            },
            'timestamp': '2026-03-18T11:00:00'
        }
        return jsonify({'status': 'success', 'data': results})
    except Exception as e:
        print(f"ERROR in /api/demo: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'status': 'error', 
            'message': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/analyze-website', methods=['POST'])
def api_analyze_website():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'url': 'https://example.com',
                'ssl_tls': 'Enabled - TLSv1.2+',
                'security_headers': 'Partially Present',
                'xss_protection': 'Enabled',
                'csrf_token': 'Present',
                'outdated_libraries': False,
                'vulnerabilities': 2,
                'overall_score': 7.5
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/analyze-password', methods=['POST'])
def api_analyze_password():
    try:
        data = request.get_json()
        password = data.get('password', 'test')
        
        return jsonify({
            'status': 'success',
            'data': {
                'length': len(password),
                'strength': 'Medium',
                'score': 5,
                'entropy': 25.3,
                'crack_time': '1-2 Months',
                'feedback': ['Add special characters', 'Increase length']
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/generate-password', methods=['POST'])
def api_generate_password():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'password': 'Kx9#mL2$pQ7vW@bN',
                'strength': 'Very Strong',
                'score': 9,
                'entropy': 42.7
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/rsa-encrypt', methods=['POST'])
def api_rsa_encrypt():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'algorithm': 'RSA',
                'key_size': 2048,
                'plaintext': 'Hello World',
                'ciphertext': 'a5f3e8d9c2b7f1e4...',
                'decrypted': 'Hello World',
                'success': True
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/dsa-sign', methods=['POST'])
def api_dsa_sign():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'algorithm': 'DSA',
                'key_size': 1024,
                'message': 'Document Hash',
                'signature_r': '12345678901234567890',
                'signature_s': '98765432109876543210',
                'signature_valid': True,
                'tamper_test_result': 'Tamper Detected - Signature Invalid'
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/analyze-file', methods=['POST'])
def api_analyze_file():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'filename': 'document.pdf',
                'extension': 'pdf',
                'is_dangerous': False,
                'permissions': 'rw-r--r--',
                'status': '✓ Safe',
                'hash_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/risk-assessment', methods=['POST'])
def api_risk_assessment():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'target': 'Example Website',
                'cvss_score': 6.5,
                'severity_rating': 'Medium',
                'risk_level': 'Moderate Risk',
                'recommendation': 'Implement immediate fixes for critical vulnerabilities',
                'mitigation': 'Update software, enable HTTPS, implement WAF'
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/compliance-assessment', methods=['POST'])
def api_compliance_assessment():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'framework': 'OWASP Top 10',
                'items': {
                    'SQLi Prevention': {'status': 'PASS', 'details': 'Parameterized queries in use'},
                    'XSS Protection': {'status': 'PASS', 'details': 'Input validation enabled'},
                    'CSRF Token': {'status': 'PASS', 'details': 'CSRF tokens present'},
                    'Weak Auth': {'status': 'FAIL', 'details': 'Password policy needs improvement'}
                }
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/generate-otp', methods=['POST'])
def api_generate_otp():
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'otp_code': '432156',
                'expiry_time': '5 minutes'
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({
        'status': 'success',
        'message': 'Security Analyzer API is running',
        'version': '2.0-debug'
    })

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'status': 'error', 'message': 'Server error'}), 500

if __name__ == '__main__':
    print("\n" + "="*70)
    print("WEBSITE VULNERABILITY ANALYZER - DEBUG MODE")
    print("="*70)
    print("\n[*] Starting Flask application (DEBUG)...")
    print("[*] Access the application at: http://localhost:5000")
    print("[*] Press Ctrl+C to stop the server")
    print("\n" + "="*70 + "\n")
    
    app.run(debug=True, host='localhost', port=5000, use_reloader=False)
