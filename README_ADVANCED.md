# Website Vulnerability Analyzer - Advanced Edition (v2.0)

A comprehensive security assessment platform with advanced cryptography algorithms, risk scoring, compliance frameworks, and secure reporting capabilities.

## 🎯 Features

### 1. **Cryptography Toolkit**
- **RSA Encryption/Decryption** (2048-bit keys)
  - Asymmetric encryption implementation
  - Key pair generation and management
  - Message encryption and decryption
  - Strength validation

- **DSA Digital Signatures**
  - Digital signature generation
  - Signature verification
  - Tamper detection
  - SHA-256 hashing integration

### 2. **Password Strength Analyzer**
- Comprehensive password analysis
- Entropy calculation (bits)
- Entropy-based crack time estimation
- Character pattern detection:
  - Uppercase/Lowercase letters
  - Numeric characters
  - Special characters
- Dictionary attack detection
- Sequential character detection
- Repeating character analysis
- Strength scoring (0-10)
- Color-coded severity indicators
- Smart recommendations
- Strong password generation

### 3. **Network Security Scanner**
- **SSL/TLS Verification**
  - Protocol detection (HTTP vs HTTPS)
  - Connection encryption status

- **Security Headers Analysis**
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection
  - Header compliance scoring

- **Vulnerability Pattern Detection**
  - SQL Injection patterns
  - Cross-Site Scripting (XSS) detection
  - Event handler analysis
  - JavaScript protocol detection

- **Authentication & Authorization**
  - Authentication mechanism detection
  - CSRF token presence verification
  - Authorization header checks

- **CORS Policy Analysis**
  - Cross-Origin Resource Sharing detection
  - Policy validation

### 4. **File Security Analyzer**
- **File Integrity**
  - SHA-256 hash calculation
  - Hash comparison verification
  - MD5/SHA1 support

- **Permission Analysis**
  - World-readable detection
  - World-writable detection (CRITICAL)
  - Executable file detection
  - Suspicious permission identification

- **Content Analysis**
  - API key detection
  - Password exposure detection
  - Private key detection
  - AWS credential detection
  - Secret detection

- **Extension Safety Check**
  - Dangerous extension identification
  - Malware-prone format detection

- **Directory Scanning**
  - Recursive directory analysis
  - Bulk file assessment
  - Sensitive data location tracking

### 5. **GRC Compliance Engine**
Governance, Risk, and Compliance framework assessments:

**Supported Frameworks:**
- **OWASP Top 10** (Latest 2021 Edition)
  - A01-A10 control mappings
  - Vulnerability categorization
  - Risk recommendations

- **NIST Cybersecurity Framework**
  - AC, AU, AT, CA, CM, IA, IR, MA, MP, PS, PE, PL, RA, SA, SC, SI controls
  - Implementation status tracking
  - Gap analysis

- **ISO/IEC 27001**
  - Information Security Management System
  - 14 core control areas
  - Certification readiness assessment

- **PCI DSS** (Payment Card Industry)
  - 12 requirements validation
  - Compliance percentage calculation
  - Critical findings identification

### 6. **Risk Scoring System**
- **CVSS v3.1 Score Calculation**
  - Base score computation
  - Severity rating
  - Vector string generation
  - Remediation priority

- **Risk Assessment**
  - Likelihood factors
  - Impact assessment
  - Overall risk quantification
  - 0-10 scoring scale

- **Vulnerability Prioritization**
  - Ranked risk list
  - Severity distribution
  - Portfolio risk analysis
  - Remediation timeline

- **Portfolio Risk Management**
  - Aggregate risk scoring
  - Severity breakdown
  - Remediation plan generation
  - Actionable recommendations

### 7. **Automated Security Reports**
Multiple output formats:

- **Executive Summary** - Management-friendly overview
- **Technical Report** - Detailed vulnerability assessment
- **HTML Report** - Graphical web-based view with styling
- **CSV Export** - Spreadsheet-compatible format
- **JSON Export** - API-friendly structured data
- **Plain Text** - Standard text format
- **Compliance Report** - Framework-specific assessment

### 8. **Secure OTP Report Sharing**
- **One-Time Password (OTP) Generation**
  - Email OTP (6-digit codes, 15-min validity)
  - SMS OTP (6-digit codes, 10-min validity)
  - TOTP/HOTP support for authenticator apps

- **Secure Share Creation**
  - Time-limited access links
  - OTP-protected reports
  - Multiple access limitations
  - Recipient email tracking
  - Share revocation capability

- **Access Control**
  - OTP verification
  - Expiry validation
  - Attempt rate limiting
  - Access logging
  - Share status monitoring

## 🚀 Installation & Usage

### Prerequisites
```bash
python --version  # Python 3.7+
pip install validators requests pyyaml beautifulsoup4
```

### Basic Usage

**1. Demo Mode (Test All Features)**
```bash
python Website_Analyzer_Advanced.py --demo
```

**2. Analyze Website**
```bash
python Website_Analyzer_Advanced.py https://example.com
```

**3. Comprehensive Analysis with All Tests**
```bash
python Website_Analyzer_Advanced.py https://example.com \
  --analyze-passwords \
  --analyze-crypto \
  --risk-assessment \
  --compliance \
  -o report.txt
```

**4. Password Strength Analysis Only**
```bash
python Website_Analyzer_Advanced.py --analyze-passwords
```

**5. RSA & DSA Encryption Analysis**
```bash
python Website_Analyzer_Advanced.py --analyze-crypto
```

**6. File Security Analysis**
```bash
python Website_Analyzer_Advanced.py --analyze-file /path/to/file
```

**7. Generate Comprehensive Report**
```bash
python Website_Analyzer_Advanced.py https://example.com \
  --analyze-passwords \
  --analyze-crypto \
  --risk-assessment \
  --compliance \
  -o security_report.txt
```

**8. Create Secure OTP Share**
```bash
python Website_Analyzer_Advanced.py https://example.com \
  --secure-share \
  --recipient-email user@example.com \
  -o report.txt
```

### Command-Line Options

```
positional arguments:
  url                       Website URL to analyze

optional arguments:
  -h, --help               Show help message
  -v, --version            Show version
  --config CONFIG          Path to configuration file
  -o, --output OUTPUT      Output report file
  --analyze-passwords      Analyze password strength
  --analyze-crypto         Analyze RSA & DSA encryption
  --risk-assessment        Perform risk assessment
  --compliance             Check compliance frameworks
  --analyze-file FILE      Analyze file security
  --secure-share           Create secure OTP share
  --recipient-email EMAIL  Email for report sharing
  --demo                   Run demo analysis
```

## 📊 Sample Output

### Password Analysis
```
[*] Password Analysis: MyP@ssw0rd
    Strength: Strong ✔ Green
    Score: 7/10
    Entropy: 65.55 bits
    Recommendations:
      - Increase password length to at least 12 characters
```

### Cryptography Results
```
RSA Encryption: Strong
  Key Size: 2048 bits
  Encryption Test: ✔ Passed
  Recommendation: Key size is adequate

DSA Signatures: Strong
  Hash Algorithm: SHA-256
  Signature Verification: ✔ Valid
  Tamper Detection: ✔ Working
```

### Risk Assessment
```
Portfolio Risk Score: 5.3/10
Portfolio Severity: Medium
Critical Issues: 1
High Risk Issues: 2
Medium Issues: 3

Remediation Plan:
  IMMEDIATE: Fix 1 critical vulnerabilities
  URGENT: Fix 2 high-risk vulnerabilities within 7 days
```

## 🔐 Security Features

- **Military-grade encryption** with RSA-2048
- **Digital signatures** using DSA with SHA-256
- **Secure OTP sharing** with time-limited access
- **Multi-factor access control** for reports
- **Compliant** with OWASP, NIST, ISO27001, PCI DSS
- **Comprehensive audit logging**
- **No plaintext password storage**

## 📁 Module Structure

```
Website-Vulnerability-Analyzer-main/
├── Website_Analyzer_Advanced.py      # Main application
├── crypto_toolkit.py                 # RSA & DSA implementations
├── password_analyzer.py              # Password strength analysis
├── network_scanner.py                # Network security scanning
├── file_analyzer.py                  # File security analysis
├── grc_engine.py                     # Compliance frameworks
├── risk_scorer.py                    # Risk assessment system
├── report_generator.py               # Report generation
├── otp_sharing.py                    # OTP and secure sharing
└── README.md                         # This file
```

## 🎨 Color Coding

- 🔴 **Critical** - Immediate action required
- 🟠 **High** - Urgent remediation needed
- 🟡 **Medium** - Schedule remediation
- 🟢 **Low** - Monitor and plan
- ⚪ **Informational** - For tracking

## 📈 Example Workflow

1. **Run Demo** → Understand features
2. **Analyze Website** → Identify vulnerabilities
3. **Check Passwords** → Ensure strong authentication
4. **Test Crypto** → Verify encryption strength
5. **Risk Assessment** → Prioritize fixes
6. **Compliance Check** → Ensure framework adherence
7. **Generate Report** → Document findings
8. **Share Securely** → Distribute with OTP protection

## 🔧 Configuration

Create a `config.yml` file:

```yaml
forms: true
comments: true
passwords: true
ssl_verification: true
header_check: true
xss_detection: true
```

Then run:
```bash
python Website_Analyzer_Advanced.py https://example.com --config config.yml
```

## 📝 Supported Report Formats

- Text (.txt)
- HTML (.html) - with styling and graphics
- JSON (.json) - API integration
- CSV (.csv) - spreadsheet compatible
- PDF (via external conversion)

## 🎓 Learning Resources

This tool teaches:
- Cryptographic algorithms (RSA, DSA)
- Web application security (OWASP Top 10)
- Risk assessment methodologies (CVSS v3.1)
- Compliance frameworks (NIST, ISO27001, PCI DSS)
- Secure software development
- Vulnerability assessment

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing systems you don't own.

## 📄 License

Open source - Use responsibly for security improvements.

## 🤝 Contributing

Feel free to enhance this tool with:
- Additional encryption algorithms
- More compliance frameworks
- Advanced reporting features
- Machine learning integration
- Cloud security checks

## 📞 Support

For issues or questions, review the module documentation or test with `--demo` mode.

---

**Version:** 2.0 (Advanced Edition)  
**Last Updated:** March 2026
