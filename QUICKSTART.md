# Quick Start Guide - Security Analyzer v2.0

## 🚀 Get Started in Minutes

### 1. Run the Demo (Recommended First Step)
Most comprehensive feature demonstration:
```bash
python Website_Analyzer_Advanced.py --demo
```

**What it does:**
- Generates RSA keys and encrypts/decrypts sample data
- Creates DSA signatures and verifies them
- Analyzes password strength of sample passwords
- Performs risk assessment
- Generates comprehensive security report

**Output:** Full security analysis report with all findings

### 2. Analyze a Real Website

**Basic analysis:**
```bash
python Website_Analyzer_Advanced.py https://example.com
```

**Full analysis with all tests:**
```bash
python Website_Analyzer_Advanced.py https://example.com ^
  --analyze-passwords ^
  --analyze-crypto ^
  --risk-assessment ^
  --compliance ^
  -o report.txt
```

### 3. Password Security Check

Test password strength with examples:
```bash
python Website_Analyzer_Advanced.py --analyze-passwords
```

Try these test passwords:
- `password123` - Weak (common password)
- `MyP@ssw0rd!2024` - Strong (mixed characters)
- `Abc123` - Weak (too short)
- `Tr0pic@lFruit#2024!` - Very Strong (long + complex)

### 4. Cryptography Demonstration

Test RSA encryption and DSA signatures:
```bash
python Website_Analyzer_Advanced.py --analyze-crypto
```

Shows:
- RSA-2048 key generation
- Message encryption/decryption
- DSA signature generation
- Signature verification
- Tamper detection

### 5. File Security Analysis

Check a file for security issues:
```bash
python Website_Analyzer_Advanced.py --analyze-file "C:\path\to\file.txt"
```

Checks:
- File permissions
- Suspicious extensions
- Sensitive data exposure
- File integrity (SHA-256 hash)

### 6. Generate Report and Share Securely

Analyze website and create secure OTP share:
```bash
python Website_Analyzer_Advanced.py https://example.com ^
  --secure-share ^
  --recipient-email security@company.com ^
  -o report.txt
```

This will:
- Generate security report
- Create OTP access code
- Save share link
- Display sharing instructions

## 📊 Understanding Results

### Password Strength Levels
- 🔴 **Very Weak** (0-2/10) - Change immediately
- 🟠 **Weak** (3-4/10) - Needs improvement
- 🟡 **Fair** (5/10) - Acceptable but improve
- 🟢 **Strong** (6-7/10) - Good
- ✔️ **Very Strong** (8-10/10) - Excellent

### Risk Scores
- **Critical** (9.0-10.0) - Immediate action required
- **High** (7.0-8.9) - Urgent remediation
- **Medium** (5.0-6.9) - Schedule remediation  
- **Low** (3.0-4.9) - Monitor and plan
- **Informational** (1.0-2.9) - For tracking

### Compliance Status
- ✔️ **Compliant** - Meets framework requirements
- ⚠️ **Partially Compliant** - Some gaps exist
- ✗️ **Non-Compliant** - Significant issues

## 🎯 Common Use Cases

### Use Case 1: Security Audit
```bash
python Website_Analyzer_Advanced.py https://myapp.com ^
  --analyze-passwords ^
  --risk-assessment ^
  --compliance ^
  -o audit_report.txt
```

### Use Case 2: Compliance Check
```bash
python Website_Analyzer_Advanced.py https://myapp.com ^
  --compliance ^
  -o compliance_report.txt
```

### Use Case 3: Developer Testing
```bash
python Website_Analyzer_Advanced.py https://localhost:3000 ^
  --analyze-crypto
```

### Use Case 4: Share with Stakeholders
```bash
python Website_Analyzer_Advanced.py https://myapp.com ^
  --secure-share ^
  --recipient-email ciso@company.com
```

## 🔐 OTP Secure Sharing

When you create a secure share:

1. **You get:**
   - Access Link (can be shared via email)
   - OTP Code (share via SMS or different channel)
   - Report content (protected by OTP)

2. **Recipient receives:**
   - Access link in email
   - OTP code in SMS (or other secure channel)

3. **Recipient accesses report:**
   - Click the link
   - Enter the OTP code
   - View report securely

4. **Security features:**
   - ✔️ Time-limited (24 hours default)
   - ✔️ Limited access attempts (3 max)
   - ✔️ Can be revoked anytime
   - ✔️ Access is logged

## 📈 Report Formats

Demo includes example reports in:
- **Text (.txt)** - Plain text format
- **HTML (.html)** - Styled web view
- **JSON (.json)** - Structured data

Generate with `-o filename`:
```bash
python Website_Analyzer_Advanced.py https://example.com -o report.txt
```

## ✅ Validation

After running analysis, look for:

✅ **RSA Encryption:**
- Key Size: 2048 bits or higher
- Status: Strong
- Test: Message encrypted and decrypted correctly

✅ **DSA Signatures:**
- Algorithm: DSA with SHA-256
- Verification: ✔ Valid
- Tamper Detection: ✔ Working

✅ **Password Analysis:**
- Strength Score: 7+/10 is good
- Entropy: 60+ bits recommended
- Mix of character types

✅ **Risk Assessment:**
- No critical vulnerabilities
- Average risk < 5/10
- Clear remediation plan

✅ **Compliance:**
- OWASP: Compliant status
- NIST: 80%+ coverage
- ISO27001: Implementation gaps identified
- PCI-DSS: Requirements met

## 🆘 Troubleshooting

### RSA Key Generation Takes Too Long
The tool uses 2048-bit keys for security. Key generation may take 30-60 seconds on slower machines. This is normal - consider it part of the security feature demonstration.

### "Invalid URL" Error
Make sure URL starts with `http://` or `https://`
```bash
# Wrong
python Website_Analyzer_Advanced.py example.com

# Correct  
python Website_Analyzer_Advanced.py https://example.com
```

### File Not Found Error
Use absolute file paths:
```bash
python Website_Analyzer_Advanced.py --analyze-file "C:\Users\Admin\file.txt"
```

### Import Errors
Make sure dependencies are installed:
```bash
pip install validators requests pyyaml beautifulsoup4
```

## 📚 Learn More

- Read `README_ADVANCED.md` for detailed documentation
- Run `python Website_Analyzer_Advanced.py --help` for all options
- Check individual module files for implementation details:
  - `crypto_toolkit.py` - Cryptography
  - `password_analyzer.py` - Password analysis
  - `network_scanner.py` - Network security
  - `file_analyzer.py` - File security
  - `grc_engine.py` - Compliance
  - `risk_scorer.py` - Risk assessment
  - `report_generator.py` - Report generation
  - `otp_sharing.py` - Secure sharing

## 💡 Tips

1. **Start with demo:**
   ```bash
   python Website_Analyzer_Advanced.py --demo
   ```
   This shows all features without needing a target URL.

2. **Test on localhost:**
   Perfect for developers - analyze local apps:
   ```bash
   python Website_Analyzer_Advanced.py http://localhost:8000
   ```

3. **Save reports:**
   Always use `-o filename` to save findings:
   ```bash
   python Website_Analyzer_Advanced.py https://app.com -o findings.txt
   ```

4. **Share securely:**
   Use OTP sharing for sensitive reports:
   ```bash
   python Website_Analyzer_Advanced.py https://app.com --secure-share
   ```

5. **Batch analysis:**
   Run multiple analyses and combine results for comprehensive assessment.

---

**Need Help?** Run `--demo` first to understand the tool, then analyze your target!
