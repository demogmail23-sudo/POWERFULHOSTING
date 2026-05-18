import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

DATABASE_PATH = 'zainu_pro.db'

def init_database():
    """Sab tables create karo - advanced schema"""
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # Users table - Extended
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            storage_quota INTEGER DEFAULT 102400,
            storage_used INTEGER DEFAULT 0,
            servers_count INTEGER DEFAULT 0,
            api_keys_count INTEGER DEFAULT 0,
            subdomains_count INTEGER DEFAULT 0,
            referral_code TEXT UNIQUE,
            referred_by TEXT,
            referral_bonus INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            last_ip TEXT,
            is_active INTEGER DEFAULT 1,
            email_verified INTEGER DEFAULT 0,
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT,
            settings TEXT DEFAULT '{}'
        )
    ''')
    
    # Servers table
    c.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            folder TEXT NOT NULL,
            template TEXT DEFAULT 'blank',
            status TEXT DEFAULT 'stopped',
            port INTEGER,
            cpu_usage REAL DEFAULT 0,
            memory_usage REAL DEFAULT 0,
            disk_usage INTEGER DEFAULT 0,
            environment TEXT DEFAULT '{}',
            custom_domain TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            last_started TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Subdomains table
    c.execute('''
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER,
            subdomain TEXT NOT NULL,
            full_domain TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
    ''')
    
    # API Keys table
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            key_preview TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Activity logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Backups table
    c.execute('''
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_name TEXT UNIQUE NOT NULL,
            size INTEGER,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Sessions table (persistent)
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            ip TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Notifications
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            message TEXT,
            type TEXT DEFAULT 'info',
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Settings table
    c.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Files table (track all files)
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_hash TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
    ''')
    
    # Referrals table
    c.execute('''
        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER NOT NULL,
            referred_id INTEGER NOT NULL,
            bonus_given INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (referrer_id) REFERENCES users(id),
            FOREIGN KEY (referred_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    
    # Create admin user if not exists
    create_admin_if_not_exists()
    
    conn.close()
    print("✅ Database initialized successfully!")

def create_admin_if_not_exists():
    from auth import hash_password
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    c.execute("SELECT id FROM users WHERE username = ?", ('ZAINU121',))
    if not c.fetchone():
        import secrets
        referral_code = secrets.token_hex(4).upper()
        c.execute('''
            INSERT INTO users (username, password_hash, role, referral_code, email_verified, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('ZAINU121', hash_password('8057558009'), 'admin', referral_code, 1, 1))
        conn.commit()
        print("✅ Admin user created!")
    
    conn.close()

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    with get_db() as conn:
        c = conn.cursor()
        c.execute(query, params)
        if fetch_one:
            return c.fetchone()
        if fetch_all:
            return c.fetchall()
        return c.lastrowid

# Run this once
init_database()