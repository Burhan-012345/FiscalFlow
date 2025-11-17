#!/usr/bin/env python3
"""
Database initialization script for PythonAnywhere
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db

def init_database():
    """Initialize the database tables"""
    try:
        with app.app_context():
            print("Creating database tables...")
            db.create_all()
            print("✅ Database tables created successfully!")
            return True
    except Exception as e:
        print(f"❌ Error creating database tables: {e}")
        return False

if __name__ == "__main__":
    init_database()