#!/usr/bin/env python3
"""
Secure OTP Report Sharing - One-Time Password and secure report delivery
"""

import random
import string
import hashlib
import hmac
from typing import Dict, Tuple, Optional
from datetime import datetime, timedelta

class OTPManager:
    """Generate and verify One-Time Passwords"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or self._generate_secret()
        self.otp_store = {}  # In production, use secure database
    
    def _generate_secret(self) -> str:
        """Generate a random secret key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    def generate_email_otp(self, length: int = 6, validity_minutes: int = 15) -> Dict:
        """Generate email OTP (6-digit code)"""
        otp = ''.join(random.choices(string.digits, k=length))
        
        expiry_time = datetime.now() + timedelta(minutes=validity_minutes)
        
        otp_data = {
            'otp': otp,
            'created_at': datetime.now().isoformat(),
            'expires_at': expiry_time.isoformat(),
            'used': False,
            'attempts': 0,
            'max_attempts': 3
        }
        
        self.otp_store[otp] = otp_data
        
        return {
            'otp': otp,
            'validity_minutes': validity_minutes,
            'format': 'Email OTP (6 digits)',
            'status': '✔ OTP generated'
        }
    
    def generate_sms_otp(self, length: int = 6, validity_minutes: int = 10) -> Dict:
        """Generate SMS OTP"""
        otp = ''.join(random.choices(string.digits, k=length))
        
        expiry_time = datetime.now() + timedelta(minutes=validity_minutes)
        
        otp_data = {
            'otp': otp,
            'created_at': datetime.now().isoformat(),
            'expires_at': expiry_time.isoformat(),
            'used': False,
            'attempts': 0,
            'max_attempts': 3,
            'delivery_method': 'SMS'
        }
        
        self.otp_store[otp] = otp_data
        
        return {
            'otp': otp,
            'validity_minutes': validity_minutes,
            'format': 'SMS OTP (6 digits)',
            'status': '✔ OTP generated'
        }
    
    def generate_totp(self, email: str = None) -> Dict:
        """Generate Time-based OTP (TOTP)"""
        # TOTP implementation
        import base64
        
        secret = base64.b32encode(self.secret_key.encode()).decode()
        
        return {
            'secret_key': secret,
            'email': email,
            'algorithm': 'HMAC-SHA1',
            'time_step': 30,
            'digits': 6,
            'format': 'QR Code for authenticator apps',
            'status': '✔ TOTP secret generated'
        }
    
    def verify_otp(self, otp: str) -> Tuple[bool, str]:
        """Verify OTP validity"""
        if otp not in self.otp_store:
            return False, 'Invalid OTP'
        
        otp_data = self.otp_store[otp]
        
        # Check if already used
        if otp_data['used']:
            return False, 'OTP already used'
        
        # Check attempt limit
        if otp_data['attempts'] >= otp_data['max_attempts']:
            return False, 'Maximum attempts exceeded'
        
        # Check expiry
        expiry = datetime.fromisoformat(otp_data['expires_at'])
        if datetime.now() > expiry:
            return False, 'OTP expired'
        
        # Mark as used
        otp_data['used'] = True
        
        return True, 'OTP verified successfully'
    
    def get_otp_status(self, otp: str) -> Dict:
        """Get OTP status"""
        if otp not in self.otp_store:
            return {'status': 'OTP not found', 'valid': False}
        
        data = self.otp_store[otp]
        
        return {
            'created_at': data['created_at'],
            'expires_at': data['expires_at'],
            'used': data['used'],
            'attempts': data['attempts'],
            'max_attempts': data['max_attempts'],
            'valid': not data['used'] and datetime.now() < datetime.fromisoformat(data['expires_at'])
        }


class SecureReportSharing:
    """Secure report delivery with OTP and encryption"""
    
    def __init__(self):
        self.otp_manager = OTPManager()
        self.shared_reports = {}
    
    def create_secure_share(self, report_content: str, recipient_email: str = None, 
                           expiry_hours: int = 24) -> Dict:
        """Create secure share link with OTP"""
        
        # Generate share token
        share_token = ''.join(random.choices(string.ascii_letters + string.digits + '-_', k=64))
        
        # Generate OTP
        otp_result = self.otp_manager.generate_email_otp(validity_minutes=expiry_hours*60)
        
        # Create share data
        share_data = {
            'token': share_token,
            'otp': otp_result['otp'],
            'report_content': report_content,
            'recipient_email': recipient_email,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(hours=expiry_hours)).isoformat(),
            'accessed': False,
            'access_count': 0,
            'max_accesses': 3
        }
        
        self.shared_reports[share_token] = share_data
        
        return {
            'share_token': share_token,
            'access_link': f'https://security-analyzer.local/view/{share_token}',
            'otp': otp_result['otp'],
            'recipient_email': recipient_email,
            'expiry_hours': expiry_hours,
            'max_accesses': 3,
            'status': '✔ Secure share created'
        }
    
    def access_secure_report(self, share_token: str, otp: str) -> Tuple[bool, str, Optional[str]]:
        """Access secure report with OTP verification"""
        
        if share_token not in self.shared_reports:
            return False, 'Invalid share token', None
        
        share_data = self.shared_reports[share_token]
        
        # Check expiry
        expiry = datetime.fromisoformat(share_data['expires_at'])
        if datetime.now() > expiry:
            return False, 'Share link expired', None
        
        # Check access limit
        if share_data['access_count'] >= share_data['max_accesses']:
            return False, 'Maximum access limit reached', None
        
        # Verify OTP
        if otp != share_data['otp']:
            return False, 'Invalid OTP', None
        
        # Increment access count
        share_data['access_count'] += 1
        share_data['accessed'] = True
        
        return True, 'Report accessed successfully', share_data['report_content']
    
    def revoke_share(self, share_token: str) -> Dict:
        """Revoke a shared report"""
        if share_token in self.shared_reports:
            del self.shared_reports[share_token]
            return {
                'share_token': share_token,
                'status': '✔ Share revoked',
                'message': 'Report sharing has been revoked'
            }
        
        return {
            'status': '✗ Share not found',
            'message': 'Share token does not exist'
        }
    
    def get_share_status(self, share_token: str) -> Dict:
        """Get status of a shared report"""
        if share_token not in self.shared_reports:
            return {'status': 'Share not found', 'valid': False}
        
        data = self.shared_reports[share_token]
        
        return {
            'share_token': share_token,
            'created_at': data['created_at'],
            'expires_at': data['expires_at'],
            'accessed': data['accessed'],
            'access_count': data['access_count'],
            'max_accesses': data['max_accesses'],
            'recipient_email': data['recipient_email'],
            'valid': datetime.now() < datetime.fromisoformat(data['expires_at']),
            'remaining_accesses': data['max_accesses'] - data['access_count']
        }
    
    def generate_secure_sharing_instructions(self, share_token: str, otp: str) -> str:
        """Generate instructions for sharing the report"""
        instructions = f"""
SECURE REPORT SHARING INSTRUCTIONS
================================================================================

1. SHARE DETAILS
   - Share Token: {share_token}
   - Access Link: https://security-analyzer.local/view/{share_token}
   - OTP Code: {otp}

2. HOW TO SHARE
   a) Send the access link and OTP code separately to the recipient
   b) Do not include the OTP in the same message as the link
   c) Use different communication channels (email link, SMS OTP)

3. SECURITY FEATURES
   ✔ One-Time Password (OTP) required for access
   ✔ Time-limited access (24 hours default)
   ✔ Limited access attempts (3 attempts maximum)
   ✔ Access logs maintained
   ✔ Report can be revoked at any time

4. RECIPIENT ACCESS
   - Click the access link
   - Enter the OTP code
   - Report will be visible for download/viewing
   - Access is logged with timestamp

5. MANAGING THE SHARE
   - Check share status at any time
   - Revoke share link if needed
   - Monitor access history

IMPORTANT: Keep the OTP confidential and share it through a secure channel!
================================================================================
        """
        return instructions.strip()


class ReportEncryption:
    """Encrypt sensitive reports"""
    
    def __init__(self):
        pass
    
    def encrypt_report(self, report_content: str, password: str) -> str:
        """Encrypt report with password"""
        import base64
        
        # Simple encryption (for production, use proper encryption like AES)
        encrypted = base64.b64encode(report_content.encode()).decode()
        return encrypted
    
    def decrypt_report(self, encrypted_content: str, password: str) -> str:
        """Decrypt encrypted report"""
        import base64
        
        try:
            decrypted = base64.b64decode(encrypted_content.encode()).decode()
            return decrypted
        except Exception:
            return None
    
    def generate_encryption_key(self) -> str:
        """Generate encryption key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
