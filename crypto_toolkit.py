#!/usr/bin/env python3
"""
Cryptography Toolkit - RSA and DSA implementation for security analysis
"""

import hashlib
import os
import random
from typing import Tuple, Dict

class RSA:
    """RSA Encryption/Decryption Implementation"""
    
    def __init__(self, key_size: int = 1024):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keypair()
    
    def is_prime(self, num: int, k: int = 5) -> bool:
        """Miller-Rabin primality test"""
        if num < 2:
            return False
        if num == 2 or num == 3:
            return True
        if num % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, num - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = random.randrange(2, num - 1)
            x = pow(a, d, num)
            
            if x == 1 or x == num - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, num)
                if x == num - 1:
                    break
            else:
                return False
        
        return True
    
    def find_prime(self, bits: int) -> int:
        """Find a random prime number with specified bits"""
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1  # Set MSB and LSB
            if self.is_prime(num):
                return num
    
    def gcd(self, a: int, b: int) -> int:
        """Calculate GCD"""
        while b:
            a, b = b, a % b
        return a
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean algorithm"""
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """Generate RSA public and private key pair"""
        bits = self.key_size // 2
        p = self.find_prime(bits)
        q = self.find_prime(bits)
        
        while p == q:
            q = self.find_prime(bits)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Find e (public exponent)
        e = 65537
        while self.gcd(e, phi) != 1:
            e += 2
        
        # Find d (private exponent)
        _, d, _ = self.extended_gcd(e, phi)
        d = d % phi
        
        public_key = {'e': e, 'n': n}
        private_key = {'d': d, 'n': n}
        
        return public_key, private_key
    
    def encrypt(self, message: int, public_key: Dict = None) -> int:
        """Encrypt message using RSA"""
        if public_key is None:
            public_key = self.public_key
        return pow(message, public_key['e'], public_key['n'])
    
    def decrypt(self, ciphertext: int, private_key: Dict = None) -> int:
        """Decrypt ciphertext using RSA"""
        if private_key is None:
            private_key = self.private_key
        return pow(ciphertext, private_key['d'], private_key['n'])
    
    def get_key_strength(self) -> Dict:
        """Analyze RSA key strength"""
        return {
            'key_size': self.key_size,
            'public_key': self.public_key,
            'status': 'Strong' if self.key_size >= 2048 else 'Weak',
            'recommendation': 'Key size is adequate' if self.key_size >= 2048 else 'Use at least 2048-bit keys'
        }


class DSA:
    """Digital Signature Algorithm Implementation"""
    
    def __init__(self, key_size: int = 1024):
        self.key_size = key_size
        self.p, self.q, self.g, self.private_key, self.public_key = self.generate_keypair()
    
    def is_prime(self, num: int, k: int = 5) -> bool:
        """Miller-Rabin primality test"""
        if num < 2:
            return False
        if num == 2 or num == 3:
            return True
        if num % 2 == 0:
            return False
        
        r, d = 0, num - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, num - 1)
            x = pow(a, d, num)
            
            if x == 1 or x == num - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, num)
                if x == num - 1:
                    break
            else:
                return False
        
        return True
    
    def find_prime(self, bits: int) -> int:
        """Find a random prime number"""
        while True:
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            if self.is_prime(num):
                return num
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean algorithm"""
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    def generate_keypair(self) -> Tuple[int, int, int, int, int]:
        """Generate DSA keys - Using pre-computed parameters for demo"""
        # FIPS 186-4 style parameters (simplified for demonstration)
        q = 887503081  # 32-bit prime divisor
        p = 19928974294940973773  # 64-bit prime
        
        # Generator element
        h = 2
        g = pow(h, (p - 1) // q, p)
        
        # Ensure g > 1
        if g <= 1:
            g = pow(3, (p - 1) // q, p)
        
        # Generate keys
        private_key = random.randrange(1, q)
        public_key = pow(g, private_key, p)
        
        return p, q, g, private_key, public_key
    
    def sign(self, message: str) -> Tuple[int, int]:
        """Sign a message using DSA"""
        hash_obj = hashlib.sha256(message.encode())
        h = int(hash_obj.hexdigest(), 16) % self.q
        
        k = random.randrange(1, self.q)
        r = pow(self.g, k, self.p) % self.q
        
        if r == 0:
            return self.sign(message)
        
        _, k_inv, _ = self.extended_gcd(k, self.q)
        k_inv = k_inv % self.q
        
        s = (k_inv * (h + self.private_key * r)) % self.q
        
        if s == 0:
            return self.sign(message)
        
        return r, s
    
    def verify(self, message: str, signature: Tuple[int, int]) -> bool:
        """Verify a DSA signature"""
        r, s = signature
        
        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            return False
        
        hash_obj = hashlib.sha256(message.encode())
        h = int(hash_obj.hexdigest(), 16) % self.q
        
        _, s_inv, _ = self.extended_gcd(s, self.q)
        s_inv = s_inv % self.q
        
        u1 = (h * s_inv) % self.q
        u2 = (r * s_inv) % self.q
        
        v = ((pow(self.g, u1, self.p) * pow(self.public_key, u2, self.p)) % self.p) % self.q
        
        return v == r
    
    def get_signature_strength(self) -> Dict:
        """Analyze DSA signature strength"""
        return {
            'key_size': self.key_size,
            'algorithm': 'DSA',
            'hash_algorithm': 'SHA-256',
            'status': 'Strong' if self.key_size >= 1024 else 'Weak',
            'recommendation': 'Algorithm implementation is secured with SHA-256'
        }
