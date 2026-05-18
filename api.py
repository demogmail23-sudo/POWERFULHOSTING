"""
REST API - ZAINU HOST PRO
External applications ke liye API endpoints
"""

from flask import Blueprint, request, jsonify, session
from functools import wraps
from datetime import datetime, timedelta
import secrets

from database import get_db
from auth import verify_password, generate_jwt, verify_jwt, hash_password

# API Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# ============== API KEY AUTH ==============
def api_key_required(f):
    """API key se authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        with get_db() as conn:
            c = conn.cursor()
            from auth import verify_password
            c.execute("SELECT user_id, name, key_hash FROM api_keys")
            keys = c.fetchall()
            
            user_id = None
            for key in keys:
                if verify_password(api_key, key['key_hash']):
                    user_id = key['user_id']
                    # Update last used
                    c.execute("UPDATE api_keys SET last_used = ? WHERE user_id = ?", 
                              (datetime.now().isoformat(), user_id))
                    break
            
            if not user_id:
                return jsonify({"error": "Invalid API key"}), 401
            
            # Get user info
            c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            
            request.user_id = user['id']
            request.username = user['username']
            request.user_role = user['role']
        
        return f(*args, **kwargs)
    return decorated

# ============== PUBLIC API ==============
@api_bp.route('/health', methods=['GET'])
def api_health():
    """API health check"""
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })

# ============== USER API ==============
@api_bp.route('/user/info', methods=['GET'])
@api_key_required
def api_get_user_info():
    """Get current user info"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, username, email, role, storage_quota, storage_used,
                   servers_count, created_at
            FROM users WHERE id = ?
        """, (request.user_id,))
        user = c.fetchone()
        
        if user:
            return jsonify({
                "success": True,
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "email": user['email'],
                    "role": user['role'],
                    "storage_quota_mb": user['storage_quota'],
                    "storage_used_mb": user['storage_used'],
                    "storage_percent": round(user['storage_used'] / user['storage_quota'] * 100, 1) if user['storage_quota'] > 0 else 0,
                    "servers_count": user['servers_count'],
                    "joined": user['created_at']
                }
            })
    
    return jsonify({"error": "User not found"}), 404

@api_bp.route('/user/stats', methods=['GET'])
@api_key_required
def api_get_user_stats():
    """Get user statistics"""
    with get_db() as conn:
        c = conn.cursor()
        
        # Servers count
        c.execute("SELECT COUNT(*) as total FROM servers WHERE user_id = ?", (request.user_id,))
        servers_total = c.fetchone()['total']
        
        # Running servers
        c.execute("SELECT COUNT(*) as total FROM servers WHERE user_id = ? AND status = 'running'", (request.user_id,))
        servers_running = c.fetchone()['total']
        
        # API keys count
        c.execute("SELECT COUNT(*) as total FROM api_keys WHERE user_id = ?", (request.user_id,))
        api_keys_count = c.fetchone()['total']
        
        # Subdomains count
        c.execute("SELECT COUNT(*) as total FROM subdomains WHERE user_id = ?", (request.user_id,))
        subdomains_count = c.fetchone()['total']
        
        return jsonify({
            "success": True,
            "stats": {
                "total_servers": servers_total,
                "running_servers": servers_running,
                "api_keys": api_keys_count,
                "subdomains": subdomains_count
            }
        })

# ============== SERVERS API ==============
@api_bp.route('/servers', methods=['GET'])
@api_key_required
def api_list_servers():
    """Get all servers for user"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, name, folder, status, created_at, updated_at
            FROM servers WHERE user_id = ?
            ORDER BY created_at DESC
        """, (request.user_id,))
        servers = c.fetchall()
        
        result = []
        for server in servers:
            result.append({
                "id": server['id'],
                "name": server['name'],
                "folder": server['folder'],
                "status": server['status'],
                "created_at": server['created_at'],
                "updated_at": server['updated_at']
            })
        
        return jsonify({"success": True, "servers": result})

@api_bp.route('/server/<int:server_id>/start', methods=['POST'])
@api_key_required
def api_start_server(server_id):
    """Start a server via API"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT folder, name FROM servers WHERE id = ? AND user_id = ?", 
                  (server_id, request.user_id))
        server = c.fetchone()
        
        if not server:
            return jsonify({"error": "Server not found"}), 404
        
        # Import and call start function
        from app import start_server_by_folder
        result = start_server_by_folder(request.username, server['folder'])
        
        if result:
            return jsonify({"success": True, "message": f"Server {server['name']} started"})
        else:
            return jsonify({"error": "Failed to start server"}), 500

@api_bp.route('/server/<int:server_id>/stop', methods=['POST'])
@api_key_required
def api_stop_server(server_id):
    """Stop a server via API"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT folder, name FROM servers WHERE id = ? AND user_id = ?", 
                  (server_id, request.user_id))
        server = c.fetchone()
        
        if not server:
            return jsonify({"error": "Server not found"}), 404
        
        from app import stop_server_by_folder
        result = stop_server_by_folder(request.username, server['folder'])
        
        return jsonify({"success": True, "message": f"Server {server['name']} stopped"})

@api_bp.route('/server/<int:server_id>/status', methods=['GET'])
@api_key_required
def api_server_status(server_id):
    """Get server status"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT status, folder FROM servers WHERE id = ? AND user_id = ?", 
                  (server_id, request.user_id))
        server = c.fetchone()
        
        if not server:
            return jsonify({"error": "Server not found"}), 404
        
        return jsonify({
            "success": True,
            "server_id": server_id,
            "status": server['status']
        })

# ============== SUBDOMAIN API ==============
@api_bp.route('/subdomains', methods=['GET'])
@api_key_required
def api_list_subdomains():
    """Get all subdomains"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, subdomain, full_domain, created_at
            FROM subdomains WHERE user_id = ?
            ORDER BY created_at DESC
        """, (request.user_id,))
        subdomains = c.fetchall()
        
        result = []
        for sub in subdomains:
            result.append({
                "id": sub['id'],
                "subdomain": sub['subdomain'],
                "full_domain": sub['full_domain'],
                "created_at": sub['created_at']
            })
        
        return jsonify({"success": True, "subdomains": result})

@api_bp.route('/subdomain/create', methods=['POST'])
@api_key_required
def api_create_subdomain():
    """Create a new subdomain"""
    data = request.json
    subdomain = data.get('subdomain', '').strip()
    server_id = data.get('server_id')
    
    if not subdomain:
        return jsonify({"error": "Subdomain required"}), 400
    
    import re
    subdomain = re.sub(r'[^a-zA-Z0-9\-]', '', subdomain)
    full_domain = f"{subdomain}.zainu.host"
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Check if exists
        c.execute("SELECT id FROM subdomains WHERE full_domain = ?", (full_domain,))
        if c.fetchone():
            return jsonify({"error": "Subdomain already taken"}), 409
        
        # Check server ownership if provided
        if server_id:
            c.execute("SELECT id FROM servers WHERE id = ? AND user_id = ?", 
                      (server_id, request.user_id))
            if not c.fetchone():
                return jsonify({"error": "Server not found"}), 404
        
        c.execute("""
            INSERT INTO subdomains (user_id, server_id, subdomain, full_domain)
            VALUES (?, ?, ?, ?)
        """, (request.user_id, server_id, subdomain, full_domain))
        
        c.execute("UPDATE users SET subdomains_count = subdomains_count + 1 WHERE id = ?", 
                  (request.user_id,))
        
        return jsonify({
            "success": True,
            "domain": full_domain,
            "message": "Subdomain created successfully"
        })

# ============== API KEY MANAGEMENT ==============
@api_bp.route('/apikeys', methods=['GET'])
@api_key_required
def api_list_apikeys():
    """List all API keys"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, name, key_preview, created_at, last_used
            FROM api_keys WHERE user_id = ?
        """, (request.user_id,))
        keys = c.fetchall()
        
        result = []
        for key in keys:
            result.append({
                "id": key['id'],
                "name": key['name'],
                "key_preview": key['key_preview'],
                "created_at": key['created_at'],
                "last_used": key['last_used']
            })
        
        return jsonify({"success": True, "api_keys": result})

@api_bp.route('/apikey/generate', methods=['POST'])
@api_key_required
def api_generate_apikey():
    """Generate new API key"""
    data = request.json
    name = data.get('name', 'API Key')
    
    api_key = f"zainu_{secrets.token_urlsafe(32)}"
    key_hash = hash_password(api_key)
    key_preview = api_key[:20] + "..."
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO api_keys (user_id, name, key_hash, key_preview)
            VALUES (?, ?, ?, ?)
        """, (request.user_id, name, key_hash, key_preview))
        
        c.execute("UPDATE users SET api_keys_count = api_keys_count + 1 WHERE id = ?", 
                  (request.user_id,))
        
        return jsonify({
            "success": True,
            "api_key": api_key,
            "message": "Save this key! You won't see it again."
        })

# ============== DEPLOY API ==============
@api_bp.route('/deploy', methods=['POST'])
@api_key_required
def api_deploy():
    """Deploy code from GitHub or URL"""
    data = request.json
    repo_url = data.get('repo_url')
    server_name = data.get('server_name', 'deployed-app')
    
    if not repo_url:
        return jsonify({"error": "Repository URL required"}), 400
    
    # Import deploy function
    from app import deploy_from_git
    
    result = deploy_from_git(request.username, repo_url, server_name)
    
    if result['success']:
        return jsonify({
            "success": True,
            "server_name": server_name,
            "message": "Deployment started successfully"
        })
    else:
        return jsonify({"error": result['message']}), 500