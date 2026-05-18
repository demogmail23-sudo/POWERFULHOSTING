"""
BACKUP WORKER - ZAINU HOST PRO
Background me automatic backup lene ke liye
"""

import time
import os
import shutil
import json
import subprocess
from datetime import datetime
import threading

def create_backup():
    """Automatic backup create karo"""
    backup_name = f"auto_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_dir = "backups"
    
    os.makedirs(backup_dir, exist_ok=True)
    
    # Backup database
    if os.path.exists("zainu_pro.db"):
        shutil.copy2("zainu_pro.db", os.path.join(backup_dir, f"{backup_name}.db"))
    
    # Backup settings
    if os.path.exists("system_settings.json"):
        shutil.copy2("system_settings.json", os.path.join(backup_dir, f"{backup_name}_settings.json"))
    
    # Log backup
    with open(os.path.join(backup_dir, "backup_log.txt"), "a") as f:
        f.write(f"[{datetime.now().isoformat()}] Backup created: {backup_name}\n")
    
    # Clean old backups (keep last 30 days)
    clean_old_backups()

def clean_old_backups():
    """Purane backups delete karo"""
    backup_dir = "backups"
    retention_days = 30
    now = time.time()
    
    if os.path.exists(backup_dir):
        for filename in os.listdir(backup_dir):
            filepath = os.path.join(backup_dir, filename)
            if os.path.isfile(filepath):
                file_age = now - os.path.getmtime(filepath)
                if file_age > (retention_days * 86400):
                    os.remove(filepath)
                    print(f"Deleted old backup: {filename}")

def run_backup_worker():
    """Background worker jo har 6 ghante me backup leta hai"""
    print("[Backup Worker] Started!")
    
    while True:
        try:
            print(f"[Backup Worker] Running backup at {datetime.now().isoformat()}")
            create_backup()
            print(f"[Backup Worker] Backup completed!")
        except Exception as e:
            print(f"[Backup Worker] Error: {e}")
        
        # Wait 6 hours (21600 seconds)
        time.sleep(21600)

if __name__ == "__main__":
    run_backup_worker()