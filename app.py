import os
import json
import secrets
import shutil
import subprocess
import time
import zipfile
import threading
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, make_response
from flask_cors import CORS
from werkzeug.utils import secure_filename

from config import Config
from database import get_db, execute_query
from auth import hash_password, verify_password, generate_jwt, verify_jwt, generate_session_id, validate_username, validate_email

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY
app.permanent_session_lifetime = Config.PERMANENT_SESSION_LIFETIME

CORS(app, supports_credentials=True)

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, 'users_data')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')

for dir_path in [USERS_DIR, TEMPLATES_DIR, BACKUP_DIR, UPLOAD_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# Store running processes
running_servers = {}
server_locks = {}

# ============== DECORATORS ==============

def login_required(f):
    """Login required decorator - permanent session support"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check Flask session first
        if 'user_id' in session:
            return f(*args, **kwargs)
        
        # Check JWT token in cookies
        token = request.cookies.get('auth_token')
        if token:
            payload = verify_jwt(token)
            if payload:
                session['user_id'] = payload['user_id']
                session['username'] = payload['username']
                return f(*args, **kwargs)
        
        # Check Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            payload = verify_jwt(token)
            if payload:
                session['user_id'] = payload['user_id']
                session['username'] = payload['username']
                return f(*args, **kwargs)
        
        return jsonify({"success": False, "message": "Login required"}), 401
    return decorated

def admin_required(f):
    """Admin required decorator"""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if not user or user['role'] != 'admin':
                return jsonify({"success": False, "message": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def log_activity(user_id, username, action, details="", ip=None, user_agent=None):
    """Activity log save karo"""
    if ip is None and request:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or request.remote_addr
    if user_agent is None and request:
        user_agent = request.headers.get('User-Agent', '')
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO activity_logs (user_id, username, action, details, ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, action, details, ip, user_agent))

# ============== AUTH ROUTES ==============

@app.route('/')
def home():
    if 'user_id' in session:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if user and user['role'] == 'admin':
                return send_from_directory('templates', 'admin.html')
        return send_from_directory('templates', 'index.html')
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return send_from_directory('templates', 'login.html')

@app.route('/api/current_user')
def api_current_user():
    if 'user_id' in session:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, username, email, role, storage_quota, storage_used, 
                       servers_count, api_keys_count, subdomains_count,
                       created_at, last_login, email_verified, is_active
                FROM users WHERE id = ?
            ''', (session['user_id'],))
            user = c.fetchone()
            if user:
                return jsonify({
                    "success": True,
                    "id": user['id'],
                    "username": user['username'],
                    "email": user['email'] or '',
                    "role": user['role'],
                    "storage_quota": user['storage_quota'],
                    "storage_used": user['storage_used'] or 0,
                    "servers_count": user['servers_count'] or 0,
                    "api_keys_count": user['api_keys_count'] or 0,
                    "subdomains_count": user['subdomains_count'] or 0,
                    "created_at": user['created_at'],
                    "email_verified": user['email_verified'],
                    "is_active": user['is_active']
                })
    return jsonify({"success": False})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash, role, is_active FROM users WHERE username = ? OR email = ?", 
                  (username, username))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "message": "Invalid credentials"})
        
        if not user['is_active']:
            return jsonify({"success": False, "message": "Account disabled"})
        
        if not verify_password(password, user['password_hash']):
            return jsonify({"success": False, "message": "Invalid credentials"})
        
        # Update last login
        c.execute("UPDATE users SET last_login = ?, last_ip = ? WHERE id = ?",
                  (datetime.now().isoformat(), request.remote_addr, user['id']))
        
        # Set session - PERMANENT (kabhi logout nahi hoga!)
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        
        # Generate JWT token for permanent login
        token = generate_jwt(user['id'], user['username'])
        
        log_activity(user['id'], user['username'], "login", "User logged in successfully")
        
        response = jsonify({
            "success": True,
            "role": user['role'],
            "username": user['username']
        })
        
        # Set cookie - expires in 365 days
        max_age = 365 * 24 * 60 * 60 if remember_me else 30 * 24 * 60 * 60
        response.set_cookie('auth_token', token, max_age=max_age, httponly=True, samesite='Lax')
        
        return response

@app.route('/api/logout', methods=['POST'])
def api_logout():
    if 'user_id' in session:
        log_activity(session['user_id'], session.get('username'), "logout", "User logged out")
    session.clear()
    response = jsonify({"success": True})
    response.set_cookie('auth_token', '', expires=0)
    return response

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    referral_code = data.get('referral_code', '').strip()
    
    # Validation
    if not validate_username(username):
        return jsonify({"success": False, "message": "Username must be 3-30 chars (a-z, A-Z, 0-9, _, -)"})
    
    if email and not validate_email(email):
        return jsonify({"success": False, "message": "Invalid email format"})
    
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"})
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Check existing
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            return jsonify({"success": False, "message": "Username already taken"})
        
        if email:
            c.execute("SELECT id FROM users WHERE email = ?", (email,))
            if c.fetchone():
                return jsonify({"success": False, "message": "Email already registered"})
        
        # Generate referral code
        import secrets
        new_referral_code = secrets.token_hex(4).upper()
        
        # Find referrer
        referrer_id = None
        bonus = 0
        if referral_code:
            c.execute("SELECT id, referral_bonus FROM users WHERE referral_code = ?", (referral_code.upper(),))
            referrer = c.fetchone()
            if referrer:
                referrer_id = referrer['id']
                bonus = 100  # 100MB bonus
        
        # Create user
        password_hash = hash_password(password)
        c.execute('''
            INSERT INTO users (username, email, password_hash, referral_code, referred_by, referral_bonus)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, email or None, password_hash, new_referral_code, referrer_id, bonus))
        
        user_id = c.lastrowid
        
        # Give bonus to referrer
        if referrer_id:
            c.execute("UPDATE users SET storage_quota = storage_quota + ?, referral_bonus = referral_bonus + ? WHERE id = ?",
                      (bonus, bonus, referrer_id))
            
            # Log referral
            c.execute('''
                INSERT INTO referrals (referrer_id, referred_id, bonus_given)
                VALUES (?, ?, ?)
            ''', (referrer_id, user_id, bonus))
        
        # Create user directory
        user_dir = os.path.join(USERS_DIR, username)
        os.makedirs(user_dir, exist_ok=True)
        os.makedirs(os.path.join(user_dir, 'servers'), exist_ok=True)
        
        log_activity(user_id, username, "register", "New user registered")
        
        return jsonify({"success": True, "message": "Registration successful! Please login."})

# ============== SERVER MANAGEMENT ==============

def get_user_servers_dir(username=None):
    if username is None and 'username' in session:
        username = session['username']
    return os.path.join(USERS_DIR, username, 'servers')

def calculate_user_storage(username):
    """User ki total storage calculate karo"""
    user_dir = os.path.join(USERS_DIR, username)
    total = 0
    if os.path.exists(user_dir):
        for root, dirs, files in os.walk(user_dir):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except:
                    pass
    return total // (1024 * 1024)  # MB me

def update_user_stats(user_id, username):
    """User statistics update karo"""
    storage_used = calculate_user_storage(username)
    
    servers_dir = get_user_servers_dir(username)
    servers_count = 0
    if os.path.exists(servers_dir):
        servers_count = len([d for d in os.listdir(servers_dir) if os.path.isdir(os.path.join(servers_dir, d))])
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            UPDATE users SET storage_used = ?, servers_count = ?
            WHERE id = ?
        ''', (storage_used, servers_count, user_id))

@app.route('/api/servers/list')
@login_required
def list_servers():
    username = session['username']
    servers_dir = get_user_servers_dir(username)
    
    servers = []
    if os.path.exists(servers_dir):
        for folder in os.listdir(servers_dir):
            folder_path = os.path.join(servers_dir, folder)
            if os.path.isdir(folder_path):
                proc_key = f"{username}_{folder}"
                is_running = proc_key in running_servers and running_servers[proc_key].poll() is None
                created_at = datetime.fromtimestamp(os.path.getctime(folder_path)).isoformat()
                
                servers.append({
                    "id": folder,
                    "name": folder,
                    "status": "running" if is_running else "stopped",
                    "created_at": created_at
                })
    
    return jsonify({"success": True, "servers": servers})

@app.route('/api/server/create', methods=['POST'])
@login_required
def create_server():
    data = request.get_json()
    name = data.get('name', '').strip()
    template = data.get('template', 'blank')
    
    if not name:
        return jsonify({"success": False, "message": "Server name required"})
    
    # Sanitize name
    import re
    folder = re.sub(r'[^a-zA-Z0-9\-_]', '-', name)
    folder = folder[:100]
    
    servers_dir = get_user_servers_dir()
    target = os.path.join(servers_dir, folder)
    
    if os.path.exists(target):
        return jsonify({"success": False, "message": "Server already exists"})
    
    os.makedirs(target)
    
    # Template files
    templates_map = {
        'python': 'main.py',
        'node': 'index.js',
        'html': 'index.html',
        'react': 'index.html'
    }
    
    if template in templates_map:
        template_file = os.path.join(TEMPLATES_DIR, f"{template}.template")
        if os.path.exists(template_file):
            shutil.copy(template_file, os.path.join(target, templates_map[template]))
        else:
            # Create default file
            with open(os.path.join(target, templates_map[template]), 'w') as f:
                if template == 'python':
                    f.write('#!/usr/bin/env python3\nprint("Hello from ZAINU HOST!")\n\n# Add your Python code here\n')
                elif template == 'node':
                    f.write('console.log("Node.js server running on ZAINU HOST!");\n')
                else:
                    f.write('<!DOCTYPE html>\n<html>\n<head><title>My Server</title></head>\n<body>\n<h1>🚀 Welcome to ZAINU HOST!</h1>\n</body>\n</html>')
    
    # Save to database
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO servers (user_id, name, folder, template)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], name, folder, template))
        server_id = c.lastrowid
    
    # Update user stats
    update_user_stats(session['user_id'], session['username'])
    
    log_activity(session['user_id'], session['username'], "create_server", f"Created server: {name}")
    
    return jsonify({"success": True, "message": "Server created", "folder": folder})

@app.route('/api/server/start/<folder>', methods=['POST'])
@login_required
def start_server(folder):
    username = session['username']
    proc_key = f"{username}_{folder}"
    
    if proc_key in running_servers and running_servers[proc_key].poll() is None:
        return jsonify({"success": False, "message": "Server already running"})
    
    server_path = os.path.join(get_user_servers_dir(), folder)
    
    if not os.path.exists(server_path):
        return jsonify({"success": False, "message": "Server not found"})
    
    # Find startup file
    startup_file = None
    for f in os.listdir(server_path):
        if f.endswith(('.py', '.js', '.html')):
            startup_file = f
            break
    
    if not startup_file:
        return jsonify({"success": False, "message": "No startup file found"})
    
    log_path = os.path.join(server_path, "server.log")
    with open(log_path, 'a') as f:
        f.write(f"\n[{datetime.now().isoformat()}] Server starting...\n")
    
    log_file = open(log_path, 'a', encoding='utf-8')
    
    try:
        if startup_file.endswith('.py'):
            proc = subprocess.Popen(
                ['python3', '-u', startup_file],
                cwd=server_path,
                stdout=log_file,
                stderr=log_file
            )
        elif startup_file.endswith('.js'):
            proc = subprocess.Popen(
                ['node', startup_file],
                cwd=server_path,
                stdout=log_file,
                stderr=log_file
            )
        else:
            # HTML file - serve with simple HTTP server
            import socket
            port = 8080
            proc = subprocess.Popen(
                ['python3', '-m', 'http.server', str(port)],
                cwd=server_path,
                stdout=log_file,
                stderr=log_file
            )
        
        running_servers[proc_key] = proc
        log_activity(session['user_id'], username, "start_server", f"Started server: {folder}")
        
        return jsonify({"success": True, "message": f"Server started with {startup_file}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/server/stop/<folder>', methods=['POST'])
@login_required
def stop_server(folder):
    username = session['username']
    proc_key = f"{username}_{folder}"
    
    if proc_key in running_servers:
        try:
            proc = running_servers[proc_key]
            proc.terminate()
            proc.wait(timeout=5)
        except:
            try:
                proc.kill()
            except:
                pass
        finally:
            del running_servers[proc_key]
    
    log_activity(session['user_id'], username, "stop_server", f"Stopped server: {folder}")
    
    return jsonify({"success": True})

@app.route('/api/server/restart/<folder>', methods=['POST'])
@login_required
def restart_server(folder):
    stop_server(folder)
    time.sleep(1)
    return start_server(folder)

@app.route('/api/server/stats/<folder>')
@login_required
def server_stats(folder):
    username = session['username']
    proc_key = f"{username}_{folder}"
    running = proc_key in running_servers and running_servers[proc_key].poll() is None
    
    cpu = 0
    memory = 0
    uptime = 0
    
    if running:
        try:
            import psutil
            p = psutil.Process(running_servers[proc_key].pid)
            cpu = p.cpu_percent(interval=0.1)
            memory = p.memory_info().rss / 1024 / 1024
            uptime = time.time() - p.create_time()
        except:
            pass
    
    # Get logs
    server_path = os.path.join(get_user_servers_dir(), folder)
    log_path = os.path.join(server_path, "server.log")
    logs = ""
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                logs = f.read()[-5000:]
        except:
            pass
    
    # Count files
    files_count = 0
    if os.path.exists(server_path):
        files_count = len([f for f in os.listdir(server_path) if os.path.isfile(os.path.join(server_path, f))])
    
    return jsonify({
        "running": running,
        "cpu": round(cpu, 1),
        "memory": round(memory, 1),
        "uptime": round(uptime),
        "logs": logs,
        "files_count": files_count
    })

# ============== FILE MANAGEMENT ==============

@app.route('/api/files/list/<folder>')
@login_required
def list_files(folder):
    server_path = os.path.join(get_user_servers_dir(), folder)
    files = []
    
    if os.path.exists(server_path):
        for f in os.listdir(server_path):
            if f in ['server.log']:
                continue
            f_path = os.path.join(server_path, f)
            files.append({
                "name": f,
                "size": os.path.getsize(f_path),
                "size_kb": round(os.path.getsize(f_path) / 1024, 1),
                "is_dir": os.path.isdir(f_path),
                "modified": datetime.fromtimestamp(os.path.getmtime(f_path)).isoformat()
            })
    
    files.sort(key=lambda x: (x["is_dir"], x["name"]))
    return jsonify({"success": True, "files": files})

@app.route('/api/files/content/<folder>/<path:filename>')
@login_required
def get_file_content(folder, filename):
    file_path = os.path.join(get_user_servers_dir(), folder, filename)
    
    if not os.path.exists(file_path):
        return jsonify({"success": False, "content": ""})
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"success": True, "content": f.read()})
    except UnicodeDecodeError:
        return jsonify({"success": False, "content": "Binary file cannot be displayed"})
    except:
        return jsonify({"success": False, "content": ""})

@app.route('/api/files/save/<folder>/<path:filename>', methods=['POST'])
@login_required
def save_file_content(folder, filename):
    file_path = os.path.join(get_user_servers_dir(), folder, filename)
    data = request.json
    
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(data.get('content', ''))
        
        update_user_stats(session['user_id'], session['username'])
        log_activity(session['user_id'], session['username'], "edit_file", f"Edited: {filename}")
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/upload/<folder>', methods=['POST'])
@login_required
def upload_files(folder):
    server_path = os.path.join(get_user_servers_dir(), folder)
    uploaded = []
    
    for file_key in request.files:
        file = request.files[file_key]
        if file and file.filename:
            filename = secure_filename(file.filename)
            save_path = os.path.join(server_path, filename)
            file.save(save_path)
            uploaded.append(filename)
    
    update_user_stats(session['user_id'], session['username'])
    log_activity(session['user_id'], session['username'], "upload_files", f"Uploaded {len(uploaded)} files to {folder}")
    
    return jsonify({"success": True, "uploaded": len(uploaded)})

@app.route('/api/files/delete/<folder>', methods=['POST'])
@login_required
def delete_file(folder):
    data = request.json
    filename = data.get('name')
    
    file_path = os.path.join(get_user_servers_dir(), folder, filename)
    
    if os.path.isfile(file_path):
        os.remove(file_path)
    elif os.path.isdir(file_path):
        shutil.rmtree(file_path)
    
    update_user_stats(session['user_id'], session['username'])
    log_activity(session['user_id'], session['username'], "delete_file", f"Deleted: {filename}")
    
    return jsonify({"success": True})

@app.route('/api/files/create-folder/<folder>', methods=['POST'])
@login_required
def create_folder(folder):
    data = request.json
    folder_name = secure_filename(data.get('name', ''))
    
    if not folder_name:
        return jsonify({"success": False, "message": "Folder name required"})
    
    folder_path = os.path.join(get_user_servers_dir(), folder, folder_name)
    os.makedirs(folder_path, exist_ok=True)
    
    return jsonify({"success": True})

# ============== SUBDOMAIN ROUTES ==============

@app.route('/api/subdomain/create', methods=['POST'])
@login_required
def create_subdomain():
    data = request.json
    subdomain = data.get('subdomain', '').strip()
    server_folder = data.get('server_folder', '')
    
    if not subdomain:
        return jsonify({"success": False, "message": "Subdomain required"})
    
    import re
    subdomain = re.sub(r'[^a-zA-Z0-9\-]', '', subdomain)
    full_domain = f"{subdomain}.zainu.host"
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM subdomains WHERE full_domain = ?", (full_domain,))
        if c.fetchone():
            return jsonify({"success": False, "message": "Subdomain already taken"})
        
        # Get server ID if provided
        server_id = None
        if server_folder:
            c.execute("SELECT id FROM servers WHERE folder = ? AND user_id = ?", 
                      (server_folder, session['user_id']))
            server = c.fetchone()
            if server:
                server_id = server['id']
        
        c.execute('''
            INSERT INTO subdomains (user_id, server_id, subdomain, full_domain)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], server_id, subdomain, full_domain))
        
        # Update user subdomains count
        c.execute("UPDATE users SET subdomains_count = subdomains_count + 1 WHERE id = ?", 
                  (session['user_id'],))
    
    log_activity(session['user_id'], session['username'], "create_subdomain", f"Created: {full_domain}")
    
    return jsonify({"success": True, "domain": full_domain, "message": f"Subdomain created: {full_domain}"})

@app.route('/api/subdomain/list')
@login_required
def list_subdomains():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT s.id, s.subdomain, s.full_domain, s.created_at, 
                   sv.name as server_name, sv.folder as server_folder
            FROM subdomains s
            LEFT JOIN servers sv ON s.server_id = sv.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
        ''', (session['user_id'],))
        subdomains = c.fetchall()
        
        result = []
        for sub in subdomains:
            result.append({
                "id": sub['id'],
                "subdomain": sub['subdomain'],
                "full_domain": sub['full_domain'],
                "created_at": sub['created_at'],
                "server_name": sub['server_name'] or 'Not assigned',
                "server_folder": sub['server_folder'] or ''
            })
    
    return jsonify({"success": True, "subdomains": result})

# ============== API KEYS ==============

@app.route('/api/apikeys/generate', methods=['POST'])
@login_required
def generate_api_key():
    data = request.json
    name = data.get('name', 'API Key')
    
    import secrets
    api_key = f"zainu_{secrets.token_urlsafe(32)}"
    key_hash = hash_password(api_key)
    key_preview = api_key[:20] + "..."
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO api_keys (user_id, name, key_hash, key_preview)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], name, key_hash, key_preview))
        
        c.execute("UPDATE users SET api_keys_count = api_keys_count + 1 WHERE id = ?", 
                  (session['user_id'],))
    
    log_activity(session['user_id'], session['username'], "generate_api_key", f"Created: {name}")
    
    return jsonify({"success": True, "api_key": api_key})

@app.route('/api/apikeys/list')
@login_required
def list_api_keys():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT id, name, key_preview, created_at, last_used, is_active
            FROM api_keys
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (session['user_id'],))
        keys = c.fetchall()
        
        result = []
        for key in keys:
            result.append({
                "id": key['id'],
                "name": key['name'],
                "key_preview": key['key_preview'],
                "created_at": key['created_at'],
                "last_used": key['last_used'],
                "is_active": key['is_active']
            })
    
    return jsonify({"success": True, "api_keys": result})

@app.route('/api/apikeys/revoke', methods=['POST'])
@login_required
def revoke_api_key():
    data = request.json
    key_id = data.get('key_id')
    
    if not key_id:
        return jsonify({"success": False, "message": "Key ID required"})
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM api_keys WHERE id = ? AND user_id = ?", (key_id, session['user_id']))
        c.execute("UPDATE users SET api_keys_count = api_keys_count - 1 WHERE id = ?", 
                  (session['user_id'],))
    
    log_activity(session['user_id'], session['username'], "revoke_api_key", f"Revoked key ID: {key_id}")
    
    return jsonify({"success": True})

# ============== USER STATS ==============

@app.route('/api/user/stats')
@login_required
def get_user_stats():
    update_user_stats(session['user_id'], session['username'])
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT storage_used, storage_quota, servers_count, api_keys_count, subdomains_count,
                   referral_code, referral_bonus
            FROM users WHERE id = ?
        ''', (session['user_id'],))
        user = c.fetchone()
        
        if user:
            return jsonify({
                "success": True,
                "storage_used": user['storage_used'],
                "storage_quota": user['storage_quota'],
                "storage_percent": round((user['storage_used'] / user['storage_quota']) * 100, 1) if user['storage_quota'] > 0 else 0,
                "servers_count": user['servers_count'],
                "api_keys_count": user['api_keys_count'],
                "subdomains_count": user['subdomains_count'],
                "referral_code": user['referral_code'],
                "referral_bonus": user['referral_bonus']
            })
    
    return jsonify({"success": False})

@app.route('/api/user/update', methods=['POST'])
@login_required
def update_user():
    data = request.json
    email = data.get('email', '')
    new_password = data.get('password', '')
    
    with get_db() as conn:
        c = conn.cursor()
        
        if email:
            c.execute("UPDATE users SET email = ? WHERE id = ?", (email, session['user_id']))
        
        if new_password and len(new_password) >= 6:
            password_hash = hash_password(new_password)
            c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, session['user_id']))
            log_activity(session['user_id'], session['username'], "change_password", "Password changed")
        elif new_password:
            return jsonify({"success": False, "message": "Password must be 6+ characters"})
    
    return jsonify({"success": True, "message": "Profile updated"})

# ============== ACTIVITY LOGS ==============

@app.route('/api/activity/logs')
@login_required
def get_activity_logs():
    limit = request.args.get('limit', 50, type=int)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT action, details, ip, timestamp
            FROM activity_logs
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (session['user_id'], limit))
        logs = c.fetchall()
        
        result = []
        for log in logs:
            result.append({
                "action": log['action'],
                "details": log['details'] or '',
                "ip": log['ip'] or '',
                "timestamp": log['timestamp']
            })
    
    return jsonify({"success": True, "logs": result})

# ============== ADMIN ROUTES ==============

@app.route('/api/admin/users')
@admin_required
def admin_get_users():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT id, username, email, role, storage_quota, storage_used, 
                   servers_count, api_keys_count, subdomains_count,
                   created_at, last_login, last_ip, is_active, email_verified
            FROM users
            ORDER BY created_at DESC
        ''')
        users = c.fetchall()
        
        result = []
        for user in users:
            result.append({
                "id": user['id'],
                "username": user['username'],
                "email": user['email'] or '',
                "role": user['role'],
                "storage_quota": user['storage_quota'],
                "storage_used": user['storage_used'] or 0,
                "servers_count": user['servers_count'] or 0,
                "api_keys_count": user['api_keys_count'] or 0,
                "subdomains_count": user['subdomains_count'] or 0,
                "created_at": user['created_at'],
                "last_login": user['last_login'],
                "last_ip": user['last_ip'] or '',
                "is_active": user['is_active'],
                "email_verified": user['email_verified']
            })
    
    return jsonify({"success": True, "users": result})

@app.route('/api/admin/delete-user', methods=['POST'])
@admin_required
def admin_delete_user():
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({"success": False, "message": "User ID required"})
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "message": "User not found or cannot delete admin"})
        
        # Delete user directory
        user_dir = os.path.join(USERS_DIR, user['username'])
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)
        
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    return jsonify({"success": True, "message": "User deleted"})

@app.route('/api/admin/activity-logs')
@admin_required
def admin_activity_logs():
    limit = request.args.get('limit', 100, type=int)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT username, action, details, ip, timestamp
            FROM activity_logs
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        logs = c.fetchall()
        
        result = []
        for log in logs:
            result.append({
                "username": log['username'],
                "action": log['action'],
                "details": log['details'] or '',
                "ip": log['ip'] or '',
                "timestamp": log['timestamp']
            })
    
    return jsonify({"success": True, "logs": result})

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    with get_db() as conn:
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) as total FROM users")
        total_users = c.fetchone()['total']
        
        c.execute("SELECT COUNT(*) as total FROM servers")
        total_servers = c.fetchone()['total']
        
        c.execute("SELECT SUM(storage_used) as total FROM users")
        total_storage = c.fetchone()['total'] or 0
        
        c.execute("SELECT COUNT(*) as total FROM api_keys")
        total_api_keys = c.fetchone()['total']
        
        c.execute("SELECT COUNT(*) as total FROM subdomains")
        total_subdomains = c.fetchone()['total']
        
        # Active users today
        today = datetime.now().date().isoformat()
        c.execute("SELECT COUNT(*) as total FROM users WHERE date(last_login) = ?", (today,))
        active_today = c.fetchone()['total']
    
    return jsonify({
        "success": True,
        "stats": {
            "total_users": total_users,
            "total_servers": total_servers,
            "total_storage": total_storage,
            "total_api_keys": total_api_keys,
            "total_subdomains": total_subdomains,
            "active_today": active_today
        }
    })

# ============== BACKUP ROUTES ==============

@app.route('/api/admin/backup', methods=['POST'])
@admin_required
def create_backup():
    backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    # Backup database
    shutil.copy2(DATABASE_PATH, f"{backup_path}.db")
    
    # Backup settings
    if os.path.exists('settings.json'):
        shutil.copy2('settings.json', f"{backup_path}_settings.json")
    
    # Calculate size
    size = os.path.getsize(f"{backup_path}.db") // (1024 * 1024)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO backups (backup_name, size, created_by)
            VALUES (?, ?, ?)
        ''', (backup_name, size, session['username']))
    
    log_activity(session['user_id'], session['username'], "create_backup", f"Created backup: {backup_name}")
    
    return jsonify({"success": True, "backup_name": backup_name, "size_mb": size})

# ============== TEMPLATES ==============

@app.route('/api/templates')
@login_required
def get_templates():
    templates = [
        {"id": "blank", "name": "Blank Project", "icon": "📄", "description": "Start from scratch"},
        {"id": "python", "name": "Python App", "icon": "🐍", "description": "Python/Flask template"},
        {"id": "node", "name": "Node.js App", "icon": "💚", "description": "Node.js/Express template"},
        {"id": "html", "name": "Static Website", "icon": "🌐", "description": "HTML/CSS/JS site"},
        {"id": "react", "name": "React App", "icon": "⚛️", "description": "React.js template"}
    ]
    return jsonify({"success": True, "templates": templates})

# ============== SYSTEM INFO ==============

@app.route('/api/system/info')
def system_info():
    import psutil
    return jsonify({
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory": {
            "total": psutil.virtual_memory().total // (1024**2),
            "used": psutil.virtual_memory().used // (1024**2),
            "percent": psutil.virtual_memory().percent
        },
        "disk": {
            "total": psutil.disk_usage('/').total // (1024**3),
            "used": psutil.disk_usage('/').used // (1024**3),
            "percent": psutil.disk_usage('/').percent
        },
        "uptime": time.time() - psutil.boot_time()
    })

# ============== ANNOUNCEMENT ==============

@app.route('/api/announcement')
def get_announcement():
    announcement = "Welcome to ZAINU HOST PRO! 🚀 Unlimited features, permanent sessions, 24/7 uptime!"
    return jsonify({"announcement": announcement, "maintenance_mode": False})

# ============== RUN SERVER ==============

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║     🚀 ZAINU HOST PRO - ULTIMATE HOSTING PLATFORM       ║
    ║                                                          ║
    ║     ✅ Database: Initialized                             ║
    ║     ✅ Session: Permanent (Kabhi logout nahi hoga)       ║
    ║     ✅ Features: Unlimited servers, subdomains, API keys ║
    ║     ✅ Admin: zainu121 / 8057558009                      ║
    ║                                                          ║
    ║     🌐 Server running on port {port}                       ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)