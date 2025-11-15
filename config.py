import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///fiscalflow.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email Configuration - Updated with better settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'fiscalflow.service@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'dtgo vxbp lcwi duek'  
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'fiscalflow.service@gmail.com'
    
    # Email connection settings
    MAIL_DEBUG = False
    MAIL_SUPPRESS_SEND = False
    MAIL_MAX_EMAILS = None
    
    # Security
    WTF_CSRF_ENABLED = True
    REMEMBER_COOKIE_DURATION = timedelta(days=30)
    SESSION_PROTECTION = 'strong'
    
    # File Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
    
    # Application URLs
    FISCALFLOW_NAME = 'FiscalFlow'
    
    @property
    def FISCALFLOW_URL(self):
        if os.environ.get('PYTHONANYWHERE_DOMAIN'):
            username = os.environ.get('PYTHONANYWHERE_USERNAME', 'fiscal01')
            domain = os.environ.get('PYTHONANYWHERE_DOMAIN', 'pythonanywhere.com')
            return f'https://{username}.{domain}'
        else:
            return os.environ.get('FISCALFLOW_URL') or 'http://localhost:5000'
    
    @property
    def IS_PRODUCTION(self):
        return 'PYTHONANYWHERE_DOMAIN' in os.environ
    
    @property
    def IS_DEVELOPMENT(self):
        return not self.IS_PRODUCTION