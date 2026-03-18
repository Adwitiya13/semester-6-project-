#!/usr/bin/env python3
"""
Password Strength Analyzer - Comprehensive password security analysis
"""

import re
import math
from typing import Dict, List

class PasswordAnalyzer:
    """Analyze password strength and security"""
    
    def __init__(self):
        self.common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', '111111', 'iloveyou', 'master', 'sunshine',
            'ashley', 'bailey', 'passw0rd', 'shadow', '123123'
        ]
        self.patterns = {
            'uppercase': r'[A-Z]',
            'lowercase': r'[a-z]',
            'digits': r'\d',
            'special': r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]'
        }
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (bits)"""
        char_set_size = 0
        
        if re.search(self.patterns['lowercase'], password):
            char_set_size += 26
        if re.search(self.patterns['uppercase'], password):
            char_set_size += 26
        if re.search(self.patterns['digits'], password):
            char_set_size += 10
        if re.search(self.patterns['special'], password):
            char_set_size += 32
        
        if char_set_size == 0:
            return 0
        
        entropy = len(password) * math.log2(char_set_size)
        return round(entropy, 2)
    
    def check_dictionary_attack(self, password: str) -> bool:
        """Check if password is in common passwords list"""
        return password.lower() in self.common_passwords
    
    def check_patterns(self, password: str) -> Dict[str, bool]:
        """Check for various character patterns"""
        return {
            'has_uppercase': bool(re.search(self.patterns['uppercase'], password)),
            'has_lowercase': bool(re.search(self.patterns['lowercase'], password)),
            'has_digits': bool(re.search(self.patterns['digits'], password)),
            'has_special': bool(re.search(self.patterns['special'], password))
        }
    
    def check_sequential(self, password: str) -> bool:
        """Check for sequential characters"""
        for i in range(len(password) - 2):
            if ord(password[i]) + 1 == ord(password[i+1]) and ord(password[i+1]) + 1 == ord(password[i+2]):
                return True
        return False
    
    def check_repeated(self, password: str) -> bool:
        """Check for repeated characters"""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False
    
    def analyze_password(self, password: str) -> Dict:
        """Comprehensive password analysis"""
        length = len(password)
        entropy = self.calculate_entropy(password)
        patterns = self.check_patterns(password)
        is_common = self.check_dictionary_attack(password)
        is_sequential = self.check_sequential(password)
        is_repeated = self.check_repeated(password)
        
        # Calculate strength score
        score = 0
        
        # Length scoring
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        
        # Complexity scoring
        for has_type in patterns.values():
            if has_type:
                score += 1
        
        # Entropy scoring
        if entropy >= 40:
            score += 2
        elif entropy >= 30:
            score += 1
        
        # Deductions
        if is_common:
            score -= 3
        if is_sequential:
            score -= 1
        if is_repeated:
            score -= 1
        
        score = max(0, min(score, 10))
        
        # Strength mapping
        if score >= 8:
            strength = 'Very Strong'
            color = '✔ Green'
        elif score >= 6:
            strength = 'Strong'
            color = '✔ Green'
        elif score >= 4:
            strength = 'Fair'
            color = '⚠ Yellow'
        elif score >= 2:
            strength = 'Weak'
            color = '✗ Red'
        else:
            strength = 'Very Weak'
            color = '✗ Red'
        
        recommendations = []
        
        if length < 12:
            recommendations.append('Increase password length to at least 12 characters')
        
        if not patterns['has_uppercase']:
            recommendations.append('Add uppercase letters (A-Z)')
        
        if not patterns['has_digits']:
            recommendations.append('Add numbers (0-9)')
        
        if not patterns['has_special']:
            recommendations.append('Add special characters (!@#$%^&*)')
        
        if is_common:
            recommendations.append('Avoid common passwords')
        
        if is_sequential:
            recommendations.append('Avoid sequential characters')
        
        if is_repeated:
            recommendations.append('Avoid repeating characters')
        
        if not recommendations:
            recommendations.append('Password is excellent!')
        
        return {
            'password_length': length,
            'entropy_bits': entropy,
            'character_patterns': patterns,
            'is_common_password': is_common,
            'has_sequential_chars': is_sequential,
            'has_repeated_chars': is_repeated,
            'strength_score': score,
            'strength_level': strength,
            'color_indicator': color,
            'recommendations': recommendations,
            'crack_time_estimate': self._estimate_crack_time(entropy)
        }
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password by brute force"""
        guesses_per_second = 1e10  # Assume 10 billion guesses/sec
        
        if entropy == 0:
            return 'Instant (no entropy)'
        
        time_seconds = (2 ** (entropy - 1)) / guesses_per_second
        
        if time_seconds < 1:
            return 'Less than 1 second'
        elif time_seconds < 60:
            return f'{time_seconds:.2f} seconds'
        elif time_seconds < 3600:
            return f'{time_seconds/60:.2f} minutes'
        elif time_seconds < 86400:
            return f'{time_seconds/3600:.2f} hours'
        elif time_seconds < 31536000:
            return f'{time_seconds/86400:.2f} days'
        elif time_seconds < 3153600000:
            return f'{time_seconds/31536000:.2f} years'
        else:
            return 'Centuries'
    
    def generate_strong_password(self, length: int = 16) -> str:
        """Generate a strong random password"""
        import random
        import string
        
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*()_+-=[]{}:;<>,.?'
        
        # Ensure all character types are included
        password_chars = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill the rest with random characters
        all_chars = lowercase + uppercase + digits + special
        password_chars.extend(random.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle to avoid pattern
        random.shuffle(password_chars)
        
        return ''.join(password_chars)
