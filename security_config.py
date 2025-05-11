import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Generate encryption key if not exists
def generate_key():
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key().decode()
        with open('.env', 'w') as f:
            f.write(f'ENCRYPTION_KEY={key}\n')
    return key.encode()

# Initialize encryption
ENCRYPTION_KEY = generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Security settings
SECURITY_SETTINGS = {
    'SSL_ENABLED': True,
    'HSTS_ENABLED': True,
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Strict',
    'PERMANENT_SESSION_LIFETIME': 3600,  # 1 hour
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOGIN_TIMEOUT': 300,  # 5 minutes
    'PASSWORD_MIN_LENGTH': 6,
    'REQUIRE_SPECIAL_CHARS': True,
    'REQUIRE_NUMBERS': True,
    'REQUIRE_UPPERCASE': True,
    'REQUIRE_LOWERCASE': True,
}

# API Security
API_SECURITY = {
    'RATE_LIMIT': '200 per day',
    'RATE_LIMIT_PER_IP': '50 per hour',
    'MAX_REQUESTS_PER_MINUTE': 60,
    'API_KEY_HEADER': 'X-API-Key',
    'API_KEY_LENGTH': 32,
}

# File Security
FILE_SECURITY = {
    'ALLOWED_EXTENSIONS': {'csv', 'xlsx', 'pdf'},
    'MAX_FILE_SIZE': 10 * 1024 * 1024,  # 10MB
    'ENCRYPT_FILES': True,
    'SIGN_FILES': True,
}

def encrypt_data(data):
    """Encrypt sensitive data"""
    if isinstance(data, str):
        data = data.encode()
    return cipher_suite.encrypt(data)

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    return cipher_suite.decrypt(encrypted_data).decode()

def validate_password(password):
    """Validate password strength"""
    if len(password) < SECURITY_SETTINGS['PASSWORD_MIN_LENGTH']:
        return False, "Password too short"
    
    if SECURITY_SETTINGS['REQUIRE_SPECIAL_CHARS'] and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain special characters"
    
    if SECURITY_SETTINGS['REQUIRE_NUMBERS'] and not any(c.isdigit() for c in password):
        return False, "Password must contain numbers"
    
    if SECURITY_SETTINGS['REQUIRE_UPPERCASE'] and not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letters"
    
    if SECURITY_SETTINGS['REQUIRE_LOWERCASE'] and not any(c.islower() for c in password):
        return False, "Password must contain lowercase letters"
    
    return True, "Password is strong" 