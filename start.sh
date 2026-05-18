#!/bin/bash

# ZAINU HOST PRO - Startup Script for Render
# Yeh script Render pe server start karta hai

echo "========================================="
echo "🚀 ZAINU HOST PRO - Starting on Render"
echo "========================================="
echo ""

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=production
export PYTHONUNBUFFERED=1

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p users_data
mkdir -p backups
mkdir -p uploads
mkdir -p logs
mkdir -p static/uploads

# Initialize database
echo "🗄️ Initializing database..."
python -c "from database import init_database; init_database()"

# Check if database initialized successfully
if [ $? -eq 0 ]; then
    echo "✅ Database initialized successfully!"
else
    echo "❌ Database initialization failed!"
    exit 1
fi

# Create admin user if not exists
echo "👑 Setting up admin user..."
python -c "
from database import get_db
from auth import hash_password
import sqlite3

try:
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', ('ZAINU121',))
        if not c.fetchone():
            password_hash = hash_password('8057558009')
            c.execute('''
                INSERT INTO users (username, password_hash, role, is_active, email_verified)
                VALUES (?, ?, ?, ?, ?)
            ''', ('ZAINU121', password_hash, 'admin', 1, 1))
            print('✅ Admin user created!')
        else:
            print('✅ Admin user already exists!')
except Exception as e:
    print(f'⚠️ Admin check failed: {e}')
"

# Check what port to use
PORT=${PORT:-5000}
echo "🌐 Using port: $PORT"

# Start the server with different methods based on environment
echo "🚀 Starting ZAINU HOST PRO Server..."

# Try different startup methods
if command -v gunicorn &> /dev/null; then
    echo "Using Gunicorn with Eventlet..."
    exec gunicorn app:app \
        --worker-class eventlet \
        --workers 1 \
        --threads 4 \
        --bind 0.0.0.0:$PORT \
        --timeout 120 \
        --access-logfile logs/access.log \
        --error-logfile logs/error.log \
        --log-level info
elif command -v python3 &> /dev/null; then
    echo "Using Python directly..."
    exec python3 app.py
else
    echo "No suitable runtime found!"
    exit 1
fi