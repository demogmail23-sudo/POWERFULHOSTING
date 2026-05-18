"""
ADMIN PANEL BACKEND - ZAINU HOST PRO
Saare admin-related functions yaha hain
"""

from flask import Blueprint, request, jsonify, session
from functools import wraps
from datetime import datetime, timedelta
import json
import os
import shutil
import secrets

from database import get_db
from auth import admin_required, log_activity

# Admin Blueprint
admin_bp = Blueprint('admin', __name__)

# ============== ADMIN DECORATOR ==============
def admin_only(f):
    """Sirf admin ke liye - extra security"""
    @wraps(f)
    @admin_required
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

# ============== DASHBOARD STATS ==============
@admin_bp.route('/api/admin/dashboard/stats', methods=['GET'])
@admin_only
def get_dashboard_stats():
    """Admin dashboard ke liye saare stats"""
    with get_db() as conn:
        c = conn.cursor()
        
        # Total users
        c.execute("SELECT COUNT(*) as total FROM users")
        total_users = c.fetchone()['total']
        
        # Total servers
        c.execute("SELECT COUNT(*) as total FROM servers")
        total_servers = c.fetchone()['total']
        
        # Total storage
        c.execute("SELECT SUM(storage_used) as total FROM users")
        total_storage = c.fetchone()['total'] or 0
        
        # Active today
        today = datetime.now().date().isoformat()
        c.execute("SELECT COUNT(*) as total FROM users WHERE date(last_login) = ?", (today,))
        active_today = c.fetchone()['total']
        
        # New users this week
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        c.execute("SELECT COUNT(*) as total FROM users WHERE created_at > ?", (week_ago,))
        new_this_week = c.fetchone()['total']
        
        # Total API keys
        c.execute("SELECT COUNT(*) as total FROM api_keys")
        total_api_keys = c.fetchone()['total']
        
        # Total subdomains
        c.execute("SELECT COUNT(*) as total FROM subdomains")
        total_subdomains = c.fetchone()['total']
        
        # Server status distribution
        c.execute("""
            SELECT status, COUNT(*) as count 
            FROM servers 
            GROUP BY status
        """)
        server_status = {row['status']: row['count'] for row in c.fetchall()}
        
        return jsonify({
            "success": True,
            "stats": {
                "total_users": total_users,
                "total_servers": total_servers,
                "total_storage_mb": total_storage,
                "total_storage_gb": round(total_storage / 1024, 2),
                "active_today": active_today,
                "new_this_week": new_this_week,
                "total_api_keys": total_api_keys,
                "total_subdomains": total_subdomains,
                "servers_running": server_status.get('running', 0),
                "servers_stopped": server_status.get('stopped', 0)
            }
        })

# ============== USER MANAGEMENT ==============
@admin_bp.route('/api/admin/users/all', methods=['GET'])
@admin_only
def get_all_users_admin():
    """Saare users ki list - with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    offset = (page - 1) * per_page
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Base query
        query = """
            SELECT id, username, email, role, storage_quota, storage_used, 
                   servers_count, api_keys_count, subdomains_count,
                   created_at, last_login, last_ip, is_active, email_verified,
                   referral_code, referral_bonus
            FROM users
        """
        params = []
        
        if search:
            query += " WHERE username LIKE ? OR email LIKE ?"
            params = [f'%{search}%', f'%{search}%']
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        users = c.fetchall()
        
        # Total count
        count_query = "SELECT COUNT(*) as total FROM users"
        if search:
            count_query += " WHERE username LIKE ? OR email LIKE ?"
            c.execute(count_query, [f'%{search}%', f'%{search}%'])
        else:
            c.execute(count_query)
        total = c.fetchone()['total']
        
        result = []
        for user in users:
            result.append({
                "id": user['id'],
                "username": user['username'],
                "email": user['email'] or '',
                "role": user['role'],
                "storage_quota": user['storage_quota'],
                "storage_used": user['storage_used'] or 0,
                "storage_percent": round((user['storage_used'] or 0) / user['storage_quota'] * 100, 1) if user['storage_quota'] > 0 else 0,
                "servers_count": user['servers_count'] or 0,
                "api_keys_count": user['api_keys_count'] or 0,
                "subdomains_count": user['subdomains_count'] or 0,
                "created_at": user['created_at'],
                "last_login": user['last_login'],
                "last_ip": user['last_ip'] or '',
                "is_active": user['is_active'],
                "email_verified": user['email_verified'],
                "referral_code": user['referral_code'],
                "referral_bonus": user['referral_bonus'] or 0
            })
        
        return jsonify({
            "success": True,
            "users": result,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page
            }
        })

@admin_bp.route('/api/admin/user/<int:user_id>', methods=['GET'])
@admin_only
def get_user_details(user_id):
    """Ek specific user ki saari details"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, username, email, role, storage_quota, storage_used, 
                   servers_count, api_keys_count, subdomains_count,
                   created_at, last_login, last_ip, is_active, email_verified,
                   referral_code, referral_bonus, referred_by
            FROM users WHERE id = ?
        """, (user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "message": "User not found"})
        
        # Get user's servers
        c.execute("SELECT id, name, folder, status, created_at FROM servers WHERE user_id = ?", (user_id,))
        servers = [dict(s) for s in c.fetchall()]
        
        # Get user's activity logs
        c.execute("""
            SELECT action, details, ip, timestamp 
            FROM activity_logs 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 20
        """, (user_id,))
        activities = [dict(a) for a in c.fetchall()]
        
        return jsonify({
            "success": True,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "role": user['role'],
                "storage_quota": user['storage_quota'],
                "storage_used": user['storage_used'],
                "servers_count": user['servers_count'],
                "api_keys_count": user['api_keys_count'],
                "subdomains_count": user['subdomains_count'],
                "created_at": user['created_at'],
                "last_login": user['last_login'],
                "last_ip": user['last_ip'],
                "is_active": user['is_active'],
                "email_verified": user['email_verified'],
                "referral_code": user['referral_code'],
                "referral_bonus": user['referral_bonus'],
                "servers": servers,
                "recent_activity": activities
            }
        })

@admin_bp.route('/api/admin/user/update', methods=['POST'])
@admin_only
def admin_update_user():
    """Admin se user update karna"""
    data = request.json
    user_id = data.get('user_id')
    storage_quota = data.get('storage_quota')
    role = data.get('role')
    is_active = data.get('is_active')
    
    with get_db() as conn:
        c = conn.cursor()
        
        updates = []
        params = []
        
        if storage_quota:
            updates.append("storage_quota = ?")
            params.append(storage_quota)
        
        if role:
            updates.append("role = ?")
            params.append(role)
        
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)
        
        if updates:
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            params.append(user_id)
            c.execute(query, params)
            
            log_activity(session['user_id'], session.get('username'), 
                        "admin_update_user", f"Updated user ID: {user_id}")
        
        return jsonify({"success": True, "message": "User updated"})

@admin_bp.route('/api/admin/user/delete', methods=['POST'])
@admin_only
def admin_delete_user_full():
    """User ko complete delete karna - saara data"""
    data = request.json
    user_id = data.get('user_id')
    
    with get_db() as conn:
        c = conn.cursor()
        
        # Get username first
        c.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"success": False, "message": "User not found"})
        
        if user['role'] == 'admin':
            return jsonify({"success": False, "message": "Cannot delete admin user"})
        
        username = user['username']
        
        # Delete user's files from disk
        import os
        from config import BASE_DIR
        user_dir = os.path.join(BASE_DIR, 'users_data', username)
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)
        
        # Delete from database (cascade will handle related tables)
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        log_activity(session['user_id'], session.get('username'), 
                    "admin_delete_user", f"Deleted user: {username}")
        
        return jsonify({"success": True, "message": f"User {username} deleted"})

# ============== SERVER MANAGEMENT (ADMIN) ==============
@admin_bp.route('/api/admin/servers/all', methods=['GET'])
@admin_only
def admin_get_all_servers():
    """Saare servers ki list (admin ke liye)"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT s.id, s.name, s.folder, s.status, s.created_at, s.updated_at,
                   u.username as owner, u.id as user_id
            FROM servers s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        """)
        servers = c.fetchall()
        
        result = []
        for server in servers:
            result.append({
                "id": server['id'],
                "name": server['name'],
                "folder": server['folder'],
                "status": server['status'],
                "owner": server['owner'],
                "user_id": server['user_id'],
                "created_at": server['created_at'],
                "updated_at": server['updated_at']
            })
        
        return jsonify({"success": True, "servers": result})

@admin_bp.route('/api/admin/server/stop/<int:server_id>', methods=['POST'])
@admin_only
def admin_stop_server(server_id):
    """Admin se kisi bhi server ko stop karna"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT folder, user_id FROM servers WHERE id = ?", (server_id,))
        server = c.fetchone()
        
        if not server:
            return jsonify({"success": False, "message": "Server not found"})
        
        # Get username
        c.execute("SELECT username FROM users WHERE id = ?", (server['user_id'],))
        user = c.fetchone()
        
        if user:
            from app import running_servers
            proc_key = f"{user['username']}_{server['folder']}"
            if proc_key in running_servers:
                try:
                    running_servers[proc_key].terminate()
                    del running_servers[proc_key]
                except:
                    pass
            
            c.execute("UPDATE servers SET status = 'stopped' WHERE id = ?", (server_id,))
            
            log_activity(session['user_id'], session.get('username'), 
                        "admin_stop_server", f"Stopped server: {server['folder']} (owner: {user['username']})")
        
        return jsonify({"success": True, "message": "Server stopped"})

# ============== SYSTEM SETTINGS ==============
@admin_bp.route('/api/admin/settings', methods=['GET', 'POST'])
@admin_only
def admin_system_settings():
    """System settings get/set"""
    settings_file = 'system_settings.json'
    
    if request.method == 'GET':
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
        else:
            settings = {
                "site_name": "ZAINU HOST PRO",
                "maintenance_mode": False,
                "announcement": "Welcome to ZAINU HOST PRO! 🚀",
                "enable_registration": True,
                "default_storage_quota": 102400,
                "max_servers_per_user": 999999,
                "referral_bonus_mb": 100,
                "smtp_host": "",
                "smtp_port": 587,
                "admin_email": "admin@zainu.host"
            }
        return jsonify({"success": True, "settings": settings})
    
    else:  # POST
        data = request.json
        with open(settings_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        log_activity(session['user_id'], session.get('username'), 
                    "admin_update_settings", "Updated system settings")
        
        return jsonify({"success": True, "message": "Settings saved"})

# ============== BACKUP MANAGEMENT ==============
@admin_bp.route('/api/admin/backup/list', methods=['GET'])
@admin_only
def list_backups():
    """Saare backups ki list"""
    backup_dir = 'backups'
    backups = []
    
    if os.path.exists(backup_dir):
        for f in os.listdir(backup_dir):
            if f.endswith('.db') or f.endswith('.zip'):
                f_path = os.path.join(backup_dir, f)
                backups.append({
                    "name": f,
                    "size_mb": round(os.path.getsize(f_path) / (1024 * 1024), 2),
                    "created": datetime.fromtimestamp(os.path.getctime(f_path)).isoformat()
                })
    
    backups.sort(key=lambda x: x['created'], reverse=True)
    return jsonify({"success": True, "backups": backups})

@admin_bp.route('/api/admin/backup/restore/<backup_name>', methods=['POST'])
@admin_only
def restore_backup(backup_name):
    """Backup restore karna"""
    backup_path = os.path.join('backups', backup_name)
    
    if not os.path.exists(backup_path):
        return jsonify({"success": False, "message": "Backup not found"})
    
    # Restore logic
    if backup_name.endswith('.db'):
        import shutil
        shutil.copy2(backup_path, 'zainu_pro.db')
    
    log_activity(session['user_id'], session.get('username'), 
                "admin_restore_backup", f"Restored backup: {backup_name}")
    
    return jsonify({"success": True, "message": "Backup restored successfully"})

# ============== ACTIVITY LOGS (ADMIN) ==============
@admin_bp.route('/api/admin/logs/all', methods=['GET'])
@admin_only
def get_all_activity_logs():
    """Saare activity logs with filters"""
    limit = request.args.get('limit', 100, type=int)
    user_filter = request.args.get('user', '')
    action_filter = request.args.get('action', '')
    
    with get_db() as conn:
        c = conn.cursor()
        
        query = """
            SELECT id, username, action, details, ip, user_agent, timestamp
            FROM activity_logs
            WHERE 1=1
        """
        params = []
        
        if user_filter:
            query += " AND username LIKE ?"
            params.append(f'%{user_filter}%')
        
        if action_filter:
            query += " AND action LIKE ?"
            params.append(f'%{action_filter}%')
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        c.execute(query, params)
        logs = c.fetchall()
        
        result = []
        for log in logs:
            result.append({
                "id": log['id'],
                "username": log['username'],
                "action": log['action'],
                "details": log['details'] or '',
                "ip": log['ip'] or '',
                "user_agent": log['user_agent'] or '',
                "timestamp": log['timestamp']
            })
        
        return jsonify({"success": True, "logs": result})

# ============== SYSTEM HEALTH ==============
@admin_bp.route('/api/admin/health', methods=['GET'])
@admin_only
def system_health():
    """System ki health check"""
    import psutil
    
    return jsonify({
        "success": True,
        "health": {
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "database_size_mb": round(os.path.getsize('zainu_pro.db') / (1024 * 1024), 2) if os.path.exists('zainu_pro.db') else 0,
            "uptime_seconds": psutil.boot_time()
        }
    })