import re
import random

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password):
    """Check password strength"""
    if len(password) < 15:
        return "weak"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    score = sum([has_upper, has_lower, has_digit, has_special])
    
    if score < 3:
        return "weak"
    elif score == 3:
        return "medium"
    else:
        return "strong"

def validate_pin(pin):
    """Validate 6-digit PIN"""
    return len(pin) == 6 and pin.isdigit()

def generate_captcha():
    """Generate simple math CAPTCHA"""
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    operation = random.choice(['+', '-', '*'])
    
    if operation == '+':
        answer = a + b
    elif operation == '-':
        answer = a - b
    else:
        answer = a * b
        
    question = f"What is {a} {operation} {b}?"
    return question, answer