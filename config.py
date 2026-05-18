import os
import secrets
from datetime import timedelta

class Config:
    # Basic
    SECRET_KEY = secrets.token_hex(32)
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)  # 1 saal tak login rakhega!
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///zainu_pro.db')
    
    # Security
    BCRYPT_ROUNDS = 12
    JWT_SECRET = secrets.token_hex(64)
    JWT_EXPIRY = timedelta(days=30)
    
    # Upload
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB max upload
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'py', 'js', 'html', 'css', 'json', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'pdf', 'zip', 'tar', 'gz'}
    
    # Server
    MAX_SERVERS_PER_USER = 999999  # Unlimited
    STORAGE_QUOTA = 102400  # 100GB default
    PORT_RANGE = (10000, 20000)
    
    # Redis for caching (optional)
    REDIS_URL = os.environ.get('REDIS_URL', None)
    
    # Email
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    
    # Features
    ENABLE_SUBDOMAINS = True
    ENABLE_SSL = True
    ENABLE_BACKUPS = True
    AUTO_BACKUP_INTERVAL = 360  # 6 ghante
    
    # Admin
    ADMIN_USERNAME = "ZAINU121"
    ADMIN_PASSWORD = "8057558009"