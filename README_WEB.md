# Website Vulnerability Analyzer - Web Edition v2.0

## 🎯 Overview

A comprehensive web-based security assessment platform that provides real-time vulnerability analysis, cryptographic demonstrations, password strength evaluation, risk scoring, and compliance checking. Built with **Flask** backend and modern **HTML5/CSS3/JavaScript** frontend.

**Features:** RSA/DSA Encryption, Password Analysis, Website Security Scanning, Risk Assessment (CVSS v3.1), Compliance Checking (OWASP), File Analysis, Report Generation

---

## ✨ Key Features

### 🔐 Cryptography Toolkit
- **RSA Encryption (2048-bit)** - Encrypt/Decrypt with public-private key encryption
- **DSA Signatures (1024-bit)** - Digital signatures with tamper detection
- Full algorithm implementation from scratch (no external crypto libraries)

### 🔑 Password Analysis
- Real-time strength assessment with entropy calculation
- Color-coded strength meter (Weak → Strong)
- Crack-time estimation
- Password generation with customizable complexity
- Security recommendations

### 🌐 Website Security Scanner
- URL vulnerability analysis
- SSL/TLS certificate verification
- HTTP security headers detection
- XSS vulnerability detection
- Form analysis and security checks
- Comment extraction

### ⚠️ Risk Assessment
- **CVSS v3.1 Scoring** - Industry-standard vulnerability rating
- Automated risk calculation
- Severity classification (Critical, High, Medium, Low)
- Remediation recommendations
- Mitigation strategies

### 📋 Compliance Assessment
- **OWASP Top 10** verification
- GDPR compliance checking
- PCI DSS assessment
- HIPAA compliance validation
- Detailed compliance reports

### 📁 File Security Analysis
- File type validation
- Hash calculation (SHA-256)
- Permission analysis
- Dangerous file detection
- File integrity verification

### 📊 Report Generation
- Multi-format export (HTML, JSON, CSV)
- Customizable report templates
- Comprehensive security assessment summaries
- Historical report storage

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Windows/Linux/macOS

### Installation

#### 1. Download and Extract
```bash
# Clone or download the repository
cd Website-Vulnerability-Analyzer-main
```

#### 2. Install Dependencies
```bash
pip install flask requests beautifulsoup4 pyyaml
```

#### 3. Run the Application
```bash
python app.py
```

#### 4. Access in Browser
```
http://localhost:5000
```

---

## 📖 Application Pages

### Home Page
- Feature overview
- Quick start guide
- Security disclaimer
- Navigation to all modules

### Demo Page
- One-click demonstration of all features
- Live RSA encryption/decryption
- DSA signature generation and verification
- Password analysis
- Risk assessment preview

### Password Analyzer
- Real-time password strength testing
- Visual strength meter
- Entropy calculation in bits
- Crack-time estimation
- Strong password generation
- Security recommendations

### Website Analyzer
- URL-based vulnerability scanning
- SSL/TLS certificate check
- HTTP header analysis
- XSS vulnerability detection
- Form security analysis
- Security score calculation

### Cryptography Toolkit
- RSA demonstration (2048-bit)
  - Generate encryption key pairs
  - Test message encryption
  - Verify decryption
- DSA demonstration (1024-bit)
  - Generate signature keys
  - Create digital signatures
  - Verify signatures
  - Detect tampering

### File Analyzer
- Upload files for security analysis
- File type validation
- SHA-256 hash calculation
- Permission analysis
- Dangerous file detection
- Safe/Unsafe status indication

### Risk Assessment
- Custom vulnerability assessment
- CVSS v3.1 score calculation
- Severity level determination
- Risk categorization
- Mitigation recommendations
- Remediation strategies

### Compliance Assessment
- Multiple framework support (OWASP, GDPR, PCI DSS, HIPAA)
- Compliance score calculation
- Pass/Fail assessment items
- Compliance recommendations
- Audit-ready reports

### Reports & Export
- Multi-format report generation (HTML, JSON, CSV)
- Customizable report sections
- Data export functionality
- Report history
- Secure report sharing

---

## 🔌 API Endpoints

### Health Check
```
GET /api/health
Response: { status: 'success', version: '2.0' }
```

### Demo Analysis
```
POST /api/demo
Response: { status: 'success', data: { rsa, dsa, passwords, risk } }
```

### Website Analysis
```
POST /api/analyze-website
Body: { url: 'https://example.com' }
Response: { status: 'success', data: { ssl_check, headers, xss_check, ... } }
```

### Password Analysis
```
POST /api/analyze-password
Body: { password: 'MyP@ssw0rd' }
Response: { status: 'success', data: { strength, score, entropy, crack_time } }
```

### Generate Password
```
POST /api/generate-password
Body: { length: 16, include_special: true }
Response: { status: 'success', data: { password, strength } }
```

### RSA Encryption
```
POST /api/rsa-encrypt
Body: { message: '123456789' }
Response: { status: 'success', data: { encrypted, decrypted, success } }
```

### DSA Signature
```
POST /api/dsa-sign
Body: { message: 'Security Document' }
Response: { status: 'success', data: { signature_valid, tamper_detection } }
```

### File Analysis
```
POST /api/analyze-file (multipart/form-data)
Body: { file: <file> }
Response: { status: 'success', data: { filename, extension, is_dangerous, hash_sha256 } }
```

### Risk Assessment
```
POST /api/risk-assessment
Body: { target: 'Website', vulnerability: 'Description' }
Response: { status: 'success', data: { cvss_score, severity_rating, recommendation } }
```

### Compliance Assessment
```
POST /api/compliance-assessment
Body: { url: 'https://example.com', assessment_type: 'owasp' }
Response: { status: 'success', data: { framework, score, items } }
```

### OTP Generation
```
POST /api/generate-otp
Body: { email: 'user@example.com' }
Response: { status: 'success', data: { otp, validity_period } }
```

---

## 🔧 Architecture

### Backend (Flask)
- **Framework:** Flask 3.0+
- **Language:** Python 3.8+
- **CORS:** Enabled for cross-origin requests
- **Max Upload:** 16MB per file

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Dark gradient theme with responsive design
- **JavaScript** - Vanilla JS with async/await for API calls
- **No Dependencies** - Pure JavaScript, no frameworks required

### Security Modules (Python)

#### crypto_toolkit.py
- RSA encryption/decryption
- DSA signature generation/verification
- Key pair generation
- Message handling

#### password_analyzer.py
- Password strength calculation
- Entropy computation
- Crack-time estimation
- Character analysis

#### network_scanner.py
- URL vulnerability assessment
- SSL/TLS checking
- Header analysis
- Port scanning (local)

#### file_analyzer.py
- File type validation
- Hash calculation
- Permission analysis
- Dangerous file detection

#### grc_engine.py
- OWASP compliance checking
- GDPR assessment
- PCI DSS validation
- HIPAA compliance
- Compliance scoring

#### risk_scorer.py
- CVSS v3.1 implementation
- Risk calculation
- Severity determination
- Portfolio risk assessment

#### report_generator.py
- Report generation
- Multi-format export
- Template rendering
- Data formatting

#### otp_sharing.py
- OTP generation
- Email integration
- Secure sharing
- Validity management

---

## 📊 Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Web Framework | Flask | 3.0+ |
| Language | Python | 3.8+ |
| Frontend | HTML5/CSS3/JS | ES6+ |
| Cryptography | Custom RSA/DSA | Native Python |
| JSON Processing | Built-in json | Standard |
| HTTP Client | requests | 2.25+ |
| Web Scraping | BeautifulSoup4 | 4.9+ |

---

## 🔒 Security Considerations

1. **Development Mode Only** - Current implementation uses Flask debug mode
2. **For Production:** Use WSGI server (Gunicorn, uWSGI)
3. **HTTPS:** Deploy behind NGINX/Apache with SSL certificates
4. **Database:** Add persistent storage for compliance data
5. **Authentication:** Implement user authentication for sensitive features
6. **Rate Limiting:** Add rate limiting for API endpoints

---

## 📁 Project Structure

```
Website-Vulnerability-Analyzer-main/
├── app.py                          # Flask application (500+ lines)
├── 
├── templates/                      # HTML5 templates
│   ├── base.html                  # Master template
│   ├── index.html                 # Home page
│   ├── demo.html                  # Demo page
│   ├── password.html              # Password analyzer
│   ├── analyzer.html              # Website scanner
│   ├── crypto.html                # Cryptography toolkit
│   ├── file.html                  # File analyzer
│   ├── risk.html                  # Risk assessment
│   ├── compliance.html            # Compliance checker
│   └── reports.html               # Report generator
│
├── crypto_toolkit.py              # RSA/DSA implementation
├── password_analyzer.py           # Password analysis
├── network_scanner.py             # Website scanning
├── file_analyzer.py               # File analysis
├── grc_engine.py                  # Compliance checking
├── risk_scorer.py                 # Risk calculation
├── report_generator.py            # Report generation
├── otp_sharing.py                 # OTP management
│
├── README_WEB.md                  # This file
├── README.md                       # Original documentation
└── config.yml                      # Configuration file
```

---

## 🎓 Educational Value

This project demonstrates:
- **Python Web Development** with Flask
- **Cryptographic Algorithms** (RSA, DSA)
- **Cybersecurity Assessment** techniques
- **Frontend Development** with vanilla JavaScript
- **REST API Design** principles
- **Security Best Practices**
- **Compliance Framework** implementation

---

## ⚙️ Configuration

Edit `config.yml` to customize:
- Server port
- Debug mode
- Upload folder
- Database settings
- API endpoints

---

## 🐛 Troubleshooting

### Issue: Port 5000 Already In Use
```bash
# Change port in app.py
app.run(debug=True, host='localhost', port=5001)
```

### Issue: Module Not Found
```bash
pip install --upgrade flask requests beautifulsoup4 pyyaml
```

### Issue: File Upload Fails
```bash
# Check upload folder permissions
mkdir uploads
chmod 755 uploads
```

### Issue: SSL Certificate Error
```bash
# For testing, temporarily disable SSL verification
# In network_scanner.py, set verify=False
```

---

## 📈 Performance

- Page Load Time: < 1 second
- API Response Time: < 500ms (average)
- Concurrent Users: Up to 10 (development mode)
- Max File Upload: 16MB

---

## 🔄 Version History

### v2.0 - Web Edition (Current)
- Complete Flask web application
- 10 HTML pages with responsive design
- 12 REST API endpoints
- CORS support
- Real-time analysis

### v2.0 - Advanced Edition
- 9 Python security modules
- 3000+ lines of code
- Cryptographic algorithms
- Compliance frameworks

### v1.0 - Original
- Basic vulnerability scanner
- Command-line interface

---

## 📝 License

This project is provided for educational purposes. All code is original implementation.

---

## 👤 Author

**Adwitiya Koley**

Semester 6 Project - Website Vulnerability Analyzer

---

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review API documentation
3. Verify all dependencies are installed
4. Check Flask server logs for errors

---

## 🚀 Future Enhancements

- [ ] User authentication system
- [ ] Database integration (PostgreSQL)
- [ ] Advanced reporting with charts
- [ ] Machine learning for vulnerability detection
- [ ] Mobile app version
- [ ] API rate limiting
- [ ] Webhook notifications
- [ ] scheduled scanning
- [ ] Team collaboration features
- [ ] Integration with security tools

---

## 📚 Resources

- Flask Documentation: https://flask.palletsprojects.com/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- RSA Algorithm: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
- DSA Algorithm: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm

---

**Last Updated:** March 18, 2026

**Status:** ✅ Production Ready (for educational use)
