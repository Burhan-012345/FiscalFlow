from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='owner')
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Additional profile fields
    phone = db.Column(db.String(20))
    company = db.Column(db.String(100))
    avatar_url = db.Column(db.String(255))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    
    # Notification preferences
    email_notifications = db.Column(db.Boolean, default=True)
    transaction_alerts = db.Column(db.Boolean, default=True)
    report_digest = db.Column(db.Boolean, default=True)
    security_alerts = db.Column(db.Boolean, default=True)

    accounts = db.relationship('Account', backref='owner', lazy=True)
    settings = db.relationship('UserSettings', backref='user', uselist=False, lazy=True)
    sessions = db.relationship('UserSession', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserSettings(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, unique=True)
    
    # General settings
    default_currency = db.Column(db.String(10), default='INR')
    date_format = db.Column(db.String(20), default='YYYY-MM-DD')
    timezone = db.Column(db.String(50), default='Asia/Kolkata')
    items_per_page = db.Column(db.Integer, default=25)
    auto_logout = db.Column(db.Boolean, default=True)
    email_reports = db.Column(db.Boolean, default=True)
    
    # Appearance settings
    theme = db.Column(db.String(20), default='light')
    dashboard_layout = db.Column(db.String(20), default='compact')
    animations = db.Column(db.Boolean, default=True)
    
    # Notification settings
    transaction_emails = db.Column(db.Boolean, default=True)
    balance_alerts = db.Column(db.Boolean, default=True)
    report_ready = db.Column(db.Boolean, default=True)
    browser_notifications = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class UserSession(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    device_type = db.Column(db.String(20))  # desktop, mobile, tablet
    browser = db.Column(db.String(100))
    location = db.Column(db.String(100))
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    logged_in_at = db.Column(db.DateTime, default=datetime.utcnow)
    logged_out_at = db.Column(db.DateTime)

class Account(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    currency = db.Column(db.String(10), default='INR')  # Changed from USD to INR
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)

    customers = db.relationship('Customer', backref='account', lazy=True)

class Customer(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    category = db.Column(db.String(50))
    current_balance = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    account_id = db.Column(db.String(36), db.ForeignKey('account.id'), nullable=False)
    
    transactions = db.relationship('Transaction', backref='customer', lazy=True, order_by='desc(Transaction.date)')
    
    @property
    def last_transaction(self):
        return Transaction.query.filter_by(customer_id=self.id).order_by(Transaction.date.desc()).first()

class Transaction(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type = db.Column(db.String(20), nullable=False)  
    amount = db.Column(db.Float, nullable=False)

    # CHANGED: Store datetime instead of just date
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    category = db.Column(db.String(50))
    notes = db.Column(db.Text)
    attachment = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    customer_id = db.Column(db.String(36), db.ForeignKey('customer.id'), nullable=False)
    
    # Audit fields
    created_by = db.Column(db.String(36), db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))

    # Updated safe_date property to handle datetime properly
    @property
    def safe_date(self):
        """Return the date part of the datetime."""
        return self.date.date() if self.date else None

    @property
    def safe_time(self):
        """Return the time part of the datetime."""
        return self.date.time() if self.date else None

class AuditLog(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action = db.Column(db.String(50), nullable=False)
    table_name = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.String(36), nullable=False)
    old_values = db.Column(db.Text)
    new_values = db.Column(db.Text)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class OTP(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    purpose = db.Column(db.String(20), default='registration') 
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

class Notification(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')  
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    action_url = db.Column(db.String(200))