# utils/encryption.py
import bcrypt
import hashlib
import base64
import re

def hash_password(password):
    """Hash password using bcrypt with proper handling"""
    try:
        # Ensure password is in bytes
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Generate salt and hash
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password, salt)
        return hashed.decode('utf-8')  # Return as string for storage
    except Exception as e:
        print(f"Error hashing password: {e}")
        raise

def verify_password(password, hashed_password):
    """Verify password against its hash with proper error handling"""
    try:
        # Check if hashed_password is empty or None
        if not hashed_password:
            return False
            
        # Check if hashed_password is a bcrypt hash
        if is_bcrypt_hash(hashed_password):
            # Ensure both are in bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
            if isinstance(hashed_password, str):
                hashed_password = hashed_password.encode('utf-8')
            
            return bcrypt.checkpw(password, hashed_password)
        else:
            # It might be an old SHA256 hash (64 chars)
            if len(hashed_password) == 64:
                return hash_pin(password) == hashed_password
            return False
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def hash_pin(pin):
    """Hash PIN using SHA-256 with salt"""
    salt = "passshield_salt"  # In production, use a random salt per user
    return hashlib.sha256((pin + salt).encode('utf-8')).hexdigest()

def verify_pin(pin, hashed_pin):
    """Verify PIN against its hash"""
    return hash_pin(pin) == hashed_pin

def encrypt_data(data, key):
    """Simple encryption for demonstration (not production-ready)"""
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def decrypt_data(encrypted_data, key):
    """Simple decryption for demonstration (not production-ready)"""
    return base64.b64decode(encrypted_data.encode('utf-8')).decode('utf-8')

def is_bcrypt_hash(hashed_value):
    """Check if the given value is a bcrypt hash"""
    if not isinstance(hashed_value, str):
        return False
    return (hashed_value.startswith('$2a$') or 
            hashed_value.startswith('$2b$') or 
            hashed_value.startswith('$2y$'))