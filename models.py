"""
DATABASE MODELS - ZAINU HOST PRO
SQLAlchemy-style models (using raw SQL for simplicity)
"""

from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict
import json

@dataclass
class User:
    """User model"""
    id: int
    username: str
    email: Optional[str]
    password_hash: str
    role: str = 'user'
    storage_quota: int = 102400
    storage_used: int = 0
    servers_count: int = 0
    api_keys_count: int = 0
    subdomains_count: int = 0
    referral_code: Optional[str] = None
    referred_by: Optional[int] = None
    referral_bonus: int = 0
    created_at: str = None
    last_login: Optional[str] = None
    last_ip: Optional[str] = None
    is_active: int = 1
    email_verified: int = 0
    two_factor_enabled: int = 0
    two_factor_secret: Optional[str] = None
    settings: str = '{}'
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "storage_quota": self.storage_quota,
            "storage_used": self.storage_used,
            "servers_count": self.servers_count,
            "api_keys_count": self.api_keys_count,
            "subdomains_count": self.subdomains_count,
            "referral_code": self.referral_code,
            "referral_bonus": self.referral_bonus,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "is_active": self.is_active,
            "email_verified": self.email_verified
        }
    
    @property
    def storage_percent(self) -> float:
        if self.storage_quota > 0:
            return round((self.storage_used / self.storage_quota) * 100, 1)
        return 0


@dataclass
class Server:
    """Server model"""
    id: int
    user_id: int
    name: str
    folder: str
    template: str = 'blank'
    status: str = 'stopped'
    port: Optional[int] = None
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: int = 0
    environment: str = '{}'
    custom_domain: Optional[str] = None
    created_at: str = None
    updated_at: Optional[str] = None
    last_started: Optional[str] = None
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "folder": self.folder,
            "status": self.status,
            "template": self.template,
            "custom_domain": self.custom_domain,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    def get_env_vars(self) -> Dict:
        """Get environment variables as dict"""
        try:
            return json.loads(self.environment)
        except:
            return {}
    
    def set_env_vars(self, env_vars: Dict):
        """Set environment variables"""
        self.environment = json.dumps(env_vars)


@dataclass
class Subdomain:
    """Subdomain model"""
    id: int
    user_id: int
    server_id: Optional[int]
    subdomain: str
    full_domain: str
    created_at: str = None
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "subdomain": self.subdomain,
            "full_domain": self.full_domain,
            "created_at": self.created_at
        }


@dataclass
class APIKey:
    """API Key model"""
    id: int
    user_id: int
    name: str
    key_hash: str
    key_preview: str
    created_at: str = None
    last_used: Optional[str] = None
    is_active: int = 1
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "key_preview": self.key_preview,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "is_active": self.is_active
        }


@dataclass
class ActivityLog:
    """Activity Log model"""
    id: int
    user_id: Optional[int]
    username: str
    action: str
    details: Optional[str]
    ip: Optional[str]
    user_agent: Optional[str]
    timestamp: str = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "username": self.username,
            "action": self.action,
            "details": self.details or '',
            "ip": self.ip or '',
            "timestamp": self.timestamp
        }


@dataclass
class Backup:
    """Backup model"""
    id: int
    backup_name: str
    size: Optional[int]
    created_by: str
    created_at: str = None
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "backup_name": self.backup_name,
            "size_mb": self.size,
            "created_by": self.created_by,
            "created_at": self.created_at
        }


@dataclass
class Notification:
    """Notification model"""
    id: int
    user_id: int
    title: str
    message: str
    type: str = 'info'
    is_read: int = 0
    created_at: str = None
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "type": self.type,
            "is_read": self.is_read,
            "created_at": self.created_at
        }


# Model registry
MODELS = {
    "user": User,
    "server": Server,
    "subdomain": Subdomain,
    "api_key": APIKey,
    "activity_log": ActivityLog,
    "backup": Backup,
    "notification": Notification
}


def row_to_model(row, model_name: str):
    """Convert database row to model instance"""
    if not row:
        return None
    
    model_class = MODELS.get(model_name)
    if not model_class:
        return None
    
    # Get fields from model
    import inspect
    fields = [f.name for f in inspect.signature(model_class).parameters.values()]
    
    # Create dict with matching fields
    data = {}
    for field in fields:
        if field in row.keys():
            data[field] = row[field]
    
    return model_class(**data)


def rows_to_model(rows, model_name: str):
    """Convert multiple rows to model instances"""
    return [row_to_model(row, model_name) for row in rows] if rows else []