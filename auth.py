import hashlib
import secrets
import re
from datetime import datetime, timedelta
import jwt
from config import Config

def hash_password(password):
    """Password hash karo - secure"""
    salt = secrets.token_hex(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() + ':' + salt

def verify_password(password, hashed):
    """Password verify karo"""
    if not hashed or ':' not in hashed:
        return False
    hash_part, salt = hashed.split(':')
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return new_hash == hash_part

def generate_jwt(user_id, username):
    """JWT token generate karo - permanent session ke liye"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + Config.JWT_EXPIRY
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

def verify_jwt(token):
    """JWT token verify karo"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
        return payload
    except:
        return None

def generate_session_id():
    """Unique session ID generate karo"""
    return secrets.token_urlsafe(32)

def validate_username(username):
    """Username validate karo - alphanumeric, underscore, hyphen"""
    return bool(re.match(r'^[a-zA-Z0-9_\-]{3,30}$', username))

def validate_email(email):
    """Email validate karo"""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))