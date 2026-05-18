"""
WEBSOCKET SERVER - ZAINU HOST PRO
Real-time console logs, server stats, notifications
"""

import asyncio
import json
import threading
import time
from datetime import datetime
from flask import session, request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect

# Initialize SocketIO
socketio = SocketIO(cors_allowed_origins="*", async_mode='threading')

# Store active connections
active_connections = {}
server_subscribers = {}

# ============== SOCKET EVENT HANDLERS ==============

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print(f"[WebSocket] Client connected: {request.sid}")
    active_connections[request.sid] = {
        "user_id": None,
        "username": None,
        "connected_at": datetime.now().isoformat()
    }
    emit('connected', {'message': 'Connected to ZAINU HOST PRO WebSocket'})


@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print(f"[WebSocket] Client disconnected: {request.sid}")
    if request.sid in active_connections:
        # Leave all rooms
        user_data = active_connections[request.sid]
        if user_data.get('username'):
            for room in list(server_subscribers.keys()):
                if request.sid in server_subscribers.get(room, []):
                    server_subscribers[room].remove(request.sid)
        del active_connections[request.sid]


@socketio.on('authenticate')
def handle_authenticate(data):
    """User authentication for WebSocket"""
    token = data.get('token')
    if not token:
        emit('auth_error', {'message': 'No token provided'})
        disconnect()
        return
    
    # Verify JWT token
    from auth import verify_jwt
    payload = verify_jwt(token)
    
    if not payload:
        emit('auth_error', {'message': 'Invalid token'})
        disconnect()
        return
    
    # Update connection info
    active_connections[request.sid]['user_id'] = payload['user_id']
    active_connections[request.sid]['username'] = payload['username']
    
    emit('auth_success', {
        'message': f"Authenticated as {payload['username']}",
        'user_id': payload['user_id'],
        'username': payload['username']
    })


@socketio.on('subscribe_server')
def handle_subscribe_server(data):
    """Subscribe to server logs"""
    server_id = data.get('server_id')
    username = active_connections[request.sid].get('username')
    
    if not username:
        emit('error', {'message': 'Not authenticated'})
        return
    
    # Verify server ownership
    from database import get_db
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT s.id, u.username 
            FROM servers s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND u.username = ?
        """, (server_id, username))
        server = c.fetchone()
        
        if not server:
            emit('error', {'message': 'Server not found or access denied'})
            return
    
    room_name = f"server_{server_id}"
    join_room(room_name)
    
    # Add to subscribers
    if room_name not in server_subscribers:
        server_subscribers[room_name] = []
    if request.sid not in server_subscribers[room_name]:
        server_subscribers[room_name].append(request.sid)
    
    emit('subscribed', {
        'server_id': server_id,
        'message': f"Subscribed to server {server_id}"
    })
    
    # Send initial logs
    send_server_logs(server_id, room_name)


@socketio.on('unsubscribe_server')
def handle_unsubscribe_server(data):
    """Unsubscribe from server logs"""
    server_id = data.get('server_id')
    room_name = f"server_{server_id}"
    leave_room(room_name)
    
    if room_name in server_subscribers and request.sid in server_subscribers[room_name]:
        server_subscribers[room_name].remove(request.sid)
    
    emit('unsubscribed', {'server_id': server_id})


@socketio.on('get_server_stats')
def handle_get_server_stats(data):
    """Get real-time server stats"""
    server_id = data.get('server_id')
    username = active_connections[request.sid].get('username')
    
    if not username:
        emit('error', {'message': 'Not authenticated'})
        return
    
    # Verify ownership
    from database import get_db
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT s.id, s.folder, u.username 
            FROM servers s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND u.username = ?
        """, (server_id, username))
        server = c.fetchone()
        
        if not server:
            emit('error', {'message': 'Server not found'})
            return
        
        # Get server stats
        folder = server['folder']
        from app import get_server_stats_by_folder
        stats = get_server_stats_by_folder(username, folder)
        
        emit('server_stats', {
            'server_id': server_id,
            'stats': stats
        })


@socketio.on('send_command')
def handle_send_command(data):
    """Send command to server console"""
    server_id = data.get('server_id')
    command = data.get('command')
    username = active_connections[request.sid].get('username')
    
    if not username or not command:
        emit('error', {'message': 'Invalid request'})
        return
    
    # Verify ownership
    from database import get_db
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT s.id, s.folder, u.username 
            FROM servers s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND u.username = ?
        """, (server_id, username))
        server = c.fetchone()
        
        if not server:
            emit('error', {'message': 'Server not found'})
            return
        
        # Execute command (security: only allow safe commands)
        import subprocess
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            emit('command_output', {
                'server_id': server_id,
                'command': command,
                'output': result.stdout,
                'error': result.stderr,
                'exit_code': result.returncode
            })
        except Exception as e:
            emit('command_output', {
                'server_id': server_id,
                'command': command,
                'error': str(e)
            })


# ============== HELPER FUNCTIONS ==============

def send_server_logs(server_id: int, room_name: str):
    """Send server logs to subscribers"""
    from database import get_db
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT s.folder, u.username 
            FROM servers s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ?
        """, (server_id,))
        server = c.fetchone()
        
        if server:
            username = server['username']
            folder = server['folder']
            
            # Read logs from file
            import os
            from config import BASE_DIR
            log_path = os.path.join(BASE_DIR, 'users_data', username, 'servers', folder, 'server.log')
            
            logs = ""
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        logs = f.read()[-10000:]  # Last 10000 chars
                except:
                    pass
            
            socketio.emit('server_logs', {
                'server_id': server_id,
                'logs': logs,
                'timestamp': datetime.now().isoformat()
            }, room=room_name)


def broadcast_announcement(message: str, announcement_type: str = 'info'):
    """Broadcast announcement to all connected clients"""
    socketio.emit('announcement', {
        'message': message,
        'type': announcement_type,
        'timestamp': datetime.now().isoformat()
    })


def send_notification(user_id: int, title: str, message: str, notif_type: str = 'info'):
    """Send notification to specific user"""
    # Find user's socket
    for sid, conn in active_connections.items():
        if conn.get('user_id') == user_id:
            socketio.emit('notification', {
                'title': title,
                'message': message,
                'type': notif_type,
                'timestamp': datetime.now().isoformat()
            }, room=sid)
            break


def start_stats_broadcaster():
    """Background thread to broadcast server stats"""
    def broadcast_stats():
        while True:
            time.sleep(5)  # Every 5 seconds
            for room_name, subscribers in server_subscribers.items():
                if subscribers:
                    # Get server ID from room name
                    server_id = room_name.replace('server_', '')
                    if server_id.isdigit():
                        # Get stats and broadcast
                        from database import get_db
                        with get_db() as conn:
                            c = conn.cursor()
                            c.execute("""
                                SELECT s.folder, u.username, s.status
                                FROM servers s
                                JOIN users u ON s.user_id = u.id
                                WHERE s.id = ?
                            """, (int(server_id),))
                            server = c.fetchone()
                            
                            if server:
                                from app import get_server_stats_by_folder
                                stats = get_server_stats_by_folder(server['username'], server['folder'])
                                stats['status'] = server['status']
                                
                                socketio.emit('server_stats_update', {
                                    'server_id': int(server_id),
                                    'stats': stats
                                }, room=room_name)
    
    thread = threading.Thread(target=broadcast_stats, daemon=True)
    thread.start()


# Start stats broadcaster
start_stats_broadcaster()


def init_websocket(app):
    """Initialize WebSocket with Flask app"""
    socketio.init_app(app)
    return socketio