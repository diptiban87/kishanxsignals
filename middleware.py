from functools import wraps
from flask import request, abort, current_app
import time
import hashlib
import re

def validate_api_key(api_key):
    """Validate API key format and length"""
    if not api_key or len(api_key) != current_app.config['API_KEY_LENGTH']:
        return False
    return bool(re.match(r'^[A-Za-z0-9-_]+$', api_key))

def check_request_signature():
    """Verify request signature for API calls"""
    timestamp = request.headers.get('X-Timestamp')
    signature = request.headers.get('X-Signature')
    
    if not timestamp or not signature:
        return False
    
    # Check if timestamp is within 5 minutes
    if abs(time.time() - float(timestamp)) > 300:
        return False
    
    # Verify signature
    expected = hashlib.sha256(
        f"{timestamp}{request.path}{request.get_data()}".encode()
    ).hexdigest()
    
    return signature == expected

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get(current_app.config['API_KEY_HEADER'])
        if not api_key or not validate_api_key(api_key):
            abort(401)
        return f(*args, **kwargs)
    return decorated_function

def require_signature(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_request_signature():
            abort(401)
        return f(*args, **kwargs)
    return decorated_function

def validate_file_upload(file):
    """Validate uploaded file"""
    if not file:
        return False, "No file uploaded"
    
    # Check file extension
    if '.' not in file.filename:
        return False, "Invalid file type"
    
    extension = file.filename.rsplit('.', 1)[1].lower()
    if extension not in current_app.config['ALLOWED_EXTENSIONS']:
        return False, "File type not allowed"
    
    # Check file size
    if len(file.read()) > current_app.config['MAX_FILE_SIZE']:
        return False, "File too large"
    
    file.seek(0)  # Reset file pointer
    return True, "File valid"

def sanitize_input(data):
    """Sanitize user input"""
    if isinstance(data, str):
        # Remove potentially dangerous characters
        data = re.sub(r'[<>]', '', data)
        # Escape special characters
        data = data.replace('&', '&amp;')
        data = data.replace('"', '&quot;')
        data = data.replace("'", '&#x27;')
        data = data.replace('/', '&#x2F;')
    return data

def validate_json_schema(schema):
    """Validate JSON request body against schema"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                abort(400)
            
            data = request.get_json()
            for key, value_type in schema.items():
                if key not in data:
                    abort(400)
                if not isinstance(data[key], value_type):
                    abort(400)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator 