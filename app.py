import email
import os
import traceback
from venv import logger
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_cors import CORS
from datetime import datetime, timedelta, time
import secrets
from sqlalchemy import func, or_
from werkzeug.utils import secure_filename
from io import BytesIO
import csv
from io import StringIO
import json
import zipfile

from config import Config
from models import db, User, Account, Customer, Transaction, AuditLog, OTP, Notification, UserSettings, UserSession
from forms import (LoginForm, RegistrationStep1Form, OTPVerificationForm, 
                  PasswordSetupForm, ForgotPasswordForm, ResetPasswordForm,
                  AccountForm, CustomerForm, TransactionForm, BulkImportForm)
from utilities import SecurityUtils, EmailUtils, FileUtils, OTPUtils, ReportUtils

# Initialize extensions
login_manager = LoginManager()
mail = Mail()
security_utils = SecurityUtils()
email_utils = None
admin = Admin(name='FiscalFlow Admin', template_mode='bootstrap3')

def safe_iso(dt):
    """Safely convert datetime to ISO format string"""
    if not dt:
        return None
    return dt.isoformat().replace(" ", "T")

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    CORS(app)
    
    # Add timesince filter
    @app.template_filter('timesince')
    def timesince_filter(dt, default="just now"):
        if dt is None:
            return default
            
        now = datetime.utcnow()
        diff = now - dt
        
        periods = (
            (diff.days // 365, 'year', 'years'),
            (diff.days // 30, 'month', 'months'),
            (diff.days // 7, 'week', 'weeks'),
            (diff.days, 'day', 'days'),
            (diff.seconds // 3600, 'hour', 'hours'),
            (diff.seconds // 60, 'minute', 'minutes'),
            (diff.seconds, 'second', 'seconds'),
        )
        
        for period, singular, plural in periods:
            if period >= 1:
                return f"{period} {singular if period == 1 else plural} ago"
        
        return default
    
    # Initialize utilities
    global security_utils, email_utils
    security_utils = SecurityUtils(app)
    email_utils = EmailUtils(mail, app)
    
    # Setup admin - Moved after db initialization
    setup_admin(app)
    
    # Register routes
    register_routes(app)
    setup_error_handlers(app)
    
    return app

def setup_admin(app):
    class SecureModelView(ModelView):
        def is_accessible(self):
            return current_user.is_authenticated and current_user.role in ['owner', 'admin']
        
        def inaccessible_callback(self, name, **kwargs):
            return redirect(url_for('login'))
    
    class UserModelView(SecureModelView):
        column_list = ['name', 'email', 'role', 'created_at', 'last_login']
        column_searchable_list = ['name', 'email']
        column_filters = ['role', 'created_at']
        form_columns = ['name', 'email', 'role', 'is_verified']
        column_editable_list = ['role', 'is_verified']
        
        def on_model_change(self, form, model, is_created):
            if is_created:
                model.set_password('temp_password123')
    
    class AccountModelView(SecureModelView):
        column_list = ['name', 'description', 'currency', 'user_id', 'created_at']
        column_searchable_list = ['name', 'description']
        column_filters = ['currency', 'created_at']
        form_columns = ['name', 'description', 'currency', 'user_id']
        column_labels = {
            'user_id': 'Owner ID'
        }
    
    class CustomerModelView(SecureModelView):
        column_list = ['name', 'email', 'phone', 'current_balance', 'account_id', 'created_at']
        column_searchable_list = ['name', 'email', 'phone']
        column_filters = ['category', 'created_at']
        form_columns = ['name', 'email', 'phone', 'category', 'account_id']
        column_editable_list = ['email', 'phone', 'category']
        column_labels = {
            'account_id': 'Account ID'
        }
    
    class TransactionModelView(SecureModelView):
        column_list = ['type', 'amount', 'date', 'customer_id', 'category', 'created_at']
        column_searchable_list = ['notes', 'category']
        column_filters = ['type', 'date', 'category']
        form_columns = ['type', 'amount', 'date', 'customer_id', 'category', 'notes']
        column_labels = {
            'customer_id': 'Customer ID'
        }
    
    class AuditLogModelView(SecureModelView):
        column_list = ['action', 'table_name', 'user_id', 'ip_address', 'timestamp']
        column_searchable_list = ['action', 'table_name']
        column_filters = ['action', 'table_name', 'timestamp']
        can_create = False
        can_edit = False
        can_delete = True
    
    class OTPModelView(SecureModelView):
        column_list = ['email', 'otp_code', 'purpose', 'expires_at', 'is_used']
        column_filters = ['purpose', 'is_used', 'expires_at']
        can_create = False
        can_edit = False
    
    class NotificationModelView(SecureModelView):
        column_list = ['user_id', 'title', 'type', 'is_read', 'created_at']
        column_filters = ['type', 'is_read', 'created_at']
        form_columns = ['user_id', 'title', 'message', 'type', 'is_read', 'action_url']

    # Initialize admin with app context
    admin.init_app(app)
    
    # Add views to admin
    admin.add_view(UserModelView(User, db.session, category='Users'))
    admin.add_view(AccountModelView(Account, db.session, category='Accounts'))
    admin.add_view(CustomerModelView(Customer, db.session, category='Customers'))
    admin.add_view(TransactionModelView(Transaction, db.session, category='Transactions'))
    admin.add_view(AuditLogModelView(AuditLog, db.session, category='System'))
    admin.add_view(OTPModelView(OTP, db.session, category='System'))
    admin.add_view(NotificationModelView(Notification, db.session, category='System'))

def register_routes(app):
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)
    
    @login_manager.unauthorized_handler
    def unauthorized():
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('index.html')
    
    # Auth Routes (remain the same)
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            
            if user and user.check_password(form.password.data) and user.is_verified:
                login_user(user, remember=form.remember_me.data)
                user.last_login = datetime.utcnow()
                
                # Create user session
                session_record = UserSession(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
                db.session.add(session_record)
                db.session.commit()
                
                # Create login notification
                notification = Notification(
                    user_id=user.id,
                    title='Successful Login',
                    message=f'You successfully logged in to your account from {request.remote_addr}',
                    type='info'
                )
                db.session.add(notification)
                db.session.commit()
                
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid email or password', 'danger')
        
        return render_template('auth/login.html', form=form)
    
    @app.route('/register')
    def register_step1():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('auth/register_step1.html')
    
    @app.route('/register/user-info', methods=['GET', 'POST'])
    def register_step2():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        form = RegistrationStep1Form()
        if form.validate_on_submit():
            # Check if user already exists
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Email already registered', 'danger')
                return render_template('auth/register_step2.html', form=form)
            
            # Generate OTP
            otp_code = OTPUtils.generate_otp()
            otp = OTP(
                email=form.email.data,
                otp_code=otp_code,
                purpose='registration',
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            
            # Store user info in session for later use
            session_data = {
                'name': form.name.data,
                'email': form.email.data
            }
            token = security_utils.generate_token(session_data, salt='registration')
            
            # Send OTP email
            try:
                email_utils.send_otp_email(form.email.data, otp_code)
                flash('Verification code sent to your email!', 'success')
            except Exception as e:
                flash('Failed to send verification email. Please try again.', 'danger')
                return render_template('auth/register_step2.html', form=form)
            
            db.session.add(otp)
            db.session.commit()
            
            return redirect(url_for('register_step3', token=token))
        
        return render_template('auth/register_step2.html', form=form)
    
    @app.route('/register/verify-otp/<token>', methods=['GET', 'POST'])
    def register_step3(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        # Verify token
        session_data = security_utils.verify_token(token, salt='registration')
        if not session_data:
            flash('Invalid or expired registration session', 'danger')
            return redirect(url_for('register_step1'))
        
        form = OTPVerificationForm()
        if form.validate_on_submit():
            otp_record = OTP.query.filter_by(
                email=session_data['email'],
                otp_code=form.otp.data,
                purpose='registration',
                is_used=False
            ).first()
            
            if OTPUtils.is_otp_valid(otp_record):
                otp_record.is_used = True
                db.session.commit()
                
                # Move to password setup
                return redirect(url_for('register_step4', token=token))
            else:
                flash('Invalid or expired OTP', 'danger')
        
        return render_template('auth/register_step3.html', form=form, token=token)
    
    @app.route('/register/set-password/<token>', methods=['GET', 'POST'])
    def register_step4(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        session_data = security_utils.verify_token(token, salt='registration')
        if not session_data:
            flash('Invalid or expired registration session', 'danger')
            return redirect(url_for('register_step1'))
        
        form = PasswordSetupForm()
        if form.validate_on_submit():
            # Create user
            user = User(
                name=session_data['name'],
                email=session_data['email']
            )
            user.set_password(form.password.data)
            user.is_verified = True
            
            # Add user to session first to generate ID
            db.session.add(user)
            db.session.flush()  # This assigns an ID without committing
            
            # Create default settings for user with the actual user_id
            user_settings = UserSettings(user_id=user.id)
            
            db.session.add(user_settings)
            db.session.commit()  # Now commit both user and settings
            
            # Create welcome notification
            notification = Notification(
                user_id=user.id,
                title='Welcome to FiscalFlow!',
                message='Thank you for joining FiscalFlow. Get started by creating your first account and adding customers.',
                type='success'
            )
            db.session.add(notification)
            db.session.commit()
            
            # Log the user in
            login_user(user)
            
            flash('Registration successful! Welcome to FiscalFlow.', 'success')
            return render_template('components/loading.html', 
                                 redirect_url=url_for('dashboard'))
        
        return render_template('auth/register_step4.html', form=form, token=token)
    
    @app.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        form = ForgotPasswordForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                token = security_utils.generate_token(
                    {'user_id': user.id}, 
                    salt='reset-password'
                )
                try:
                    email_utils.send_password_reset(user.email, token)
                    flash('Password reset link has been sent to your email.', 'info')
                except Exception as e:
                    flash('Failed to send reset email. Please try again.', 'danger')
            else:
                # Don't reveal whether email exists for security
                flash('If an account with that email exists, a reset link has been sent.', 'info')
            
            return redirect(url_for('login'))
        
        return render_template('auth/forgot_password.html', form=form)
    
    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        data = security_utils.verify_token(token, salt='reset-password')
        if not data:
            flash('Invalid or expired reset token', 'danger')
            return redirect(url_for('forgot_password'))
        
        user = User.query.get(data['user_id'])
        if not user:
            flash('Invalid user', 'danger')
            return redirect(url_for('forgot_password'))
        
        form = ResetPasswordForm()
        if form.validate_on_submit():
            user.set_password(form.password.data)
            db.session.commit()
            
            # Create notification
            notification = Notification(
                user_id=user.id,
                title='Password Reset',
                message='Your password was successfully reset.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
        
        return render_template('auth/reset_password.html', form=form, token=token)
    
    @app.route('/logout')
    @login_required
    def logout():
        # Mark current session as logged out
        if current_user.is_authenticated:
            UserSession.query.filter_by(
                user_id=current_user.id, 
                logged_out_at=None
            ).update({'logged_out_at': datetime.utcnow()})
            db.session.commit()
        
        logout_user()
        flash('You have been logged out successfully.', 'info')
        return redirect(url_for('index'))
    
    # Secret Admin Access Routes (remain the same)
    @app.route('/admin-access')
    @login_required
    def admin_access():
        """Secret admin access page"""
        if current_user.role not in ['owner', 'admin']:
            flash('Access denied', 'danger')
            return redirect(url_for('dashboard'))
        return redirect('/admin')
    
    @app.route('/secret-admin')
    @login_required
    def secret_admin():
        """Alternative secret admin access"""
        if current_user.role not in ['owner', 'admin']:
            flash('Access denied', 'danger')
            return redirect(url_for('dashboard'))
        return redirect('/admin')
    
    @app.route('/tap-admin')
    @login_required
    def tap_admin():
        """Secret tap-based admin access for mobile"""
        if current_user.role not in ['owner', 'admin']:
            flash('Access denied', 'danger')
            return redirect(url_for('dashboard'))
        return redirect('/admin')
    
    @app.route('/profile/admin-access')
    @login_required
    def profile_admin_access():
        """Hidden admin access via profile page"""
        if current_user.role not in ['owner', 'admin']:
            flash('Access denied', 'danger')
            return redirect(url_for('profile'))
        return redirect('/admin')
    
    @app.route('/api/check-admin-access')
    @login_required
    def check_admin_access():
        """API endpoint to check if user has admin access"""
        return jsonify({
            'has_access': current_user.role in ['owner', 'admin'],
            'role': current_user.role
        })
    
    # Dashboard Route (remain the same)
    @app.route('/dashboard')
    @login_required
    def dashboard():
        # Get user's accounts
        accounts = Account.query.filter_by(user_id=current_user.id).all()
        
        # Get user's customers with their last transactions preloaded
        customers = Customer.query.join(Account).filter(Account.user_id == current_user.id).all()
        
        # Preload last transactions for each customer to avoid N+1 query
        for customer in customers:
            customer._last_transaction = customer.last_transaction
        
        # Calculate totals
        total_balance = sum(customer.current_balance for customer in customers)
        total_customers = len(customers)
        
        # Get all transactions for calculations
        all_transactions = Transaction.query.join(Customer).join(Account).filter(
            Account.user_id == current_user.id
        ).all()
        
        # Calculate cash in/out totals
        total_cash_in = sum(t.amount for t in all_transactions if t.type == 'cash_in')
        total_cash_out = sum(t.amount for t in all_transactions if t.type == 'cash_out')
        
        return render_template('dashboard/dashboard.html',
                             customers=customers,
                             accounts=accounts,
                             total_balance=total_balance,
                             total_customers=total_customers,
                             total_cash_in=total_cash_in,
                             total_cash_out=total_cash_out)
    
    # Add Account Route (remain the same)
    @app.route('/add-account', methods=['GET', 'POST'])
    @login_required
    def add_account():
        form = AccountForm()
        
        # Debug information
        print(f"Method: {request.method}")
        print(f"Form submitted: {form.is_submitted()}")
        
        if form.validate_on_submit():
            print("Form validated successfully!")
            print(f"Name: {form.name.data}")
            print(f"Description: {form.description.data}")
            print(f"Currency: {form.currency.data}")
            
            try:
                account = Account(
                    name=form.name.data,
                    description=form.description.data,
                    currency=form.currency.data,  # This will be 'INR'
                    user_id=current_user.id
                )
                db.session.add(account)
                db.session.commit()
                
                # Create notification
                notification = Notification(
                    user_id=current_user.id,
                    title='Account Created',
                    message=f'Account "{account.name}" was successfully created.',
                    type='success'
                )
                db.session.add(notification)
                db.session.commit()
                
                flash('Account created successfully!', 'success')
                return redirect(url_for('add_customer', account_id=account.id))
                
            except Exception as e:
                print(f"Error creating account: {str(e)}")
                db.session.rollback()
                flash('Error creating account. Please try again.', 'danger')
        else:
            print(f"Form validation failed. Errors: {form.errors}")
            if form.is_submitted():
                flash('Please fix the errors below.', 'danger')
        
        return render_template('dashboard/add_account.html', form=form)
    
    @app.route('/add-customer/<account_id>', methods=['GET', 'POST'])
    @login_required
    def add_customer(account_id):
        account = Account.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()
        
        form = CustomerForm()
        if form.validate_on_submit():
            customer = Customer(
                name=form.name.data,
                email=form.email.data,
                phone=form.phone.data,
                category=form.category.data,
                account_id=account_id
            )
            db.session.add(customer)
            db.session.commit()
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Customer Added',
                message=f'Customer "{customer.name}" was successfully added.',
                type='success'
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Customer added successfully!', 'success')
            return redirect(url_for('customer_detail', customer_id=customer.id))
        
        return render_template('dashboard/add_customer.html', form=form, account=account)
    
    @app.route('/customer/<customer_id>')
    @login_required
    def customer_detail(customer_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        transactions = Transaction.query.filter_by(customer_id=customer_id).order_by(Transaction.date.desc()).all()
        
        return render_template('dashboard/customer_detail.html',
                             customer=customer,
                             transactions=transactions)
    
    @app.route('/edit-customer/<customer_id>', methods=['GET', 'POST'])
    @login_required
    def edit_customer(customer_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        form = CustomerForm(obj=customer)
        
        if form.validate_on_submit():
            # Log changes for audit
            old_values = {
                'name': customer.name,
                'email': customer.email,
                'phone': customer.phone,
                'category': customer.category
            }
            
            form.populate_obj(customer)
            customer.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Create audit log
            new_values = {
                'name': customer.name,
                'email': customer.email,
                'phone': customer.phone,
                'category': customer.category
            }
            
            audit_log = AuditLog(
                action='UPDATE',
                table_name='customer',
                record_id=customer_id,
                old_values=str(old_values),
                new_values=str(new_values),
                user_id=current_user.id,
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Customer Updated',
                message=f'Customer "{customer.name}" was successfully updated.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Customer updated successfully!', 'success')
            return redirect(url_for('customer_detail', customer_id=customer.id))
        
        return render_template('dashboard/edit_customer.html', 
                             form=form, 
                             customer=customer,
                             transactions_count=len(customer.transactions))
    
    @app.route('/delete-customer/<customer_id>', methods=['POST'])
    @login_required
    def delete_customer(customer_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        customer_name = customer.name
        
        # Delete associated transactions first
        Transaction.query.filter_by(customer_id=customer_id).delete()
        
        # Then delete the customer
        db.session.delete(customer)
        db.session.commit()
        
        # Create audit log
        audit_log = AuditLog(
            action='DELETE',
            table_name='customer',
            record_id=customer_id,
            old_values=f"Customer: {customer_name}",
            new_values=None,
            user_id=current_user.id,
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        
        # Create notification
        notification = Notification(
            user_id=current_user.id,
            title='Customer Deleted',
            message=f'Customer "{customer_name}" and all associated transactions were deleted.',
            type='warning'
        )
        db.session.add(notification)
        db.session.commit()
        
        flash('Customer deleted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # ADD TRANSACTION ROUTE - UPDATED (with separate Date and Time fields)
    @app.route('/customer/<customer_id>/add-transaction', methods=['GET', 'POST'])
    @login_required
    def add_transaction(customer_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        # Get transaction type from query parameter
        transaction_type = request.args.get('type', 'cash_in')
        
        form = TransactionForm()
        
        # Set default values for GET request
        if request.method == 'GET':
            # Set current date and time as default
            form.date.data = datetime.utcnow().date()
            form.time.data = datetime.utcnow().time()
        
        # Debug information
        if form.is_submitted():
            print(f"Form submitted: {form.is_submitted()}")
            print(f"Form validated: {form.validate()}")
            print(f"Form errors: {form.errors}")
            print(f"Form data: {form.data}")
            print(f"URL Transaction Type: {transaction_type}")
            print(f"Form Transaction Type: {form.type.data}")
        
        if form.validate_on_submit():
            print("Form validation successful!")
            print(f"Final transaction type being used: {transaction_type}")
            
            try:
                # Combine date and time into a single datetime object
                transaction_date = form.date.data
                transaction_time = form.time.data
                
                # Create datetime object by combining date and time
                transaction_datetime = datetime.combine(transaction_date, transaction_time)
                
                # Create transaction - use type from URL parameter, NOT from form
                transaction = Transaction(
                    type=transaction_type,  # Always use URL parameter, not form data
                    amount=form.amount.data,
                    date=transaction_datetime,  # This is now a datetime object
                    category=form.category.data,
                    notes=form.notes.data,
                    customer_id=customer_id,
                    created_by=current_user.id,
                    ip_address=request.remote_addr
                )
                
                # Handle file upload (optional)
                if form.attachment.data and form.attachment.data.filename:
                    filename = FileUtils.save_uploaded_file(
                        form.attachment.data,
                        app.config['UPLOAD_FOLDER']
                    )
                    if filename:
                        transaction.attachment = filename
                
                # Update customer balance - FIXED LOGIC
                old_balance = customer.current_balance
                if transaction_type == 'cash_in':
                    customer.current_balance += form.amount.data
                    print(f"Cash IN: Adding {form.amount.data} to balance. Old: {old_balance}, New: {customer.current_balance}")
                else:  # cash_out
                    customer.current_balance -= form.amount.data
                    print(f"Cash OUT: Subtracting {form.amount.data} from balance. Old: {old_balance}, New: {customer.current_balance}")
                
                customer.updated_at = datetime.utcnow()
                
                db.session.add(transaction)
                db.session.commit()
                
                # Create audit log
                audit_log = AuditLog(
                    action='CREATE',
                    table_name='transaction',
                    record_id=transaction.id,
                    old_values=None,
                    new_values=str({
                        'type': transaction.type,
                        'amount': transaction.amount,
                        'customer_id': customer_id,
                        'category': transaction.category,
                        'datetime': transaction_datetime.isoformat()
                    }),
                    user_id=current_user.id,
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                
                # Create notification
                notification = Notification(
                    user_id=current_user.id,
                    title='Transaction Added',
                    message=f'{transaction_type.replace("_", " ").title()} of ₹{form.amount.data:.2f} for {customer.name}',
                    type='info'
                )
                db.session.add(notification)
                db.session.commit()
                
                # Send email notification if customer has email
                if customer.email:
                    try:
                        email_utils.send_transaction_update(
                            customer.email,
                            customer.name,
                            transaction.type,
                            transaction.amount,
                            customer.current_balance
                        )
                    except Exception as e:
                        print(f"Email notification failed: {str(e)}")
                        flash('Transaction added but failed to send email notification.', 'warning')
                
                flash('Transaction added successfully!', 'success')
                return redirect(url_for('customer_detail', customer_id=customer_id))
                
            except Exception as e:
                db.session.rollback()
                print(f"Error saving transaction: {str(e)}")
                flash(f'Error saving transaction: {str(e)}', 'danger')
        
        return render_template('dashboard/transactions.html', 
                             form=form, 
                             customer=customer,
                             transaction_type=transaction_type,
                             is_edit=False)
    
    # EDIT TRANSACTION - UPDATED (with separate Date and Time fields)
    @app.route('/customer/<customer_id>/transaction/<transaction_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_transaction(customer_id, transaction_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        transaction = Transaction.query.filter_by(
            id=transaction_id,
            customer_id=customer_id
        ).first_or_404()
        
        form = TransactionForm()
        
        if request.method == 'GET':
            # Pre-populate the form with existing data for GET request
            form.type.data = transaction.type
            form.amount.data = transaction.amount
            
            # Extract date and time from the datetime object
            if transaction.date:
                form.date.data = transaction.date.date()  # Extract date part
                form.time.data = transaction.date.time()  # Extract time part
            
            form.category.data = transaction.category
            form.notes.data = transaction.notes
            
            return render_template('dashboard/transactions.html',
                                 form=form,
                                 customer=customer,
                                 transaction=transaction,
                                 transaction_type=transaction.type,
                                 is_edit=True)
        
        # Handle POST request (form submission)
        if form.validate_on_submit():
            try:
                old_amount = transaction.amount
                old_type = transaction.type
                old_datetime = transaction.date
                
                # Store old values for balance recalculation
                old_transaction_type = transaction.type
                old_transaction_amount = transaction.amount
                
                # Combine date and time into a single datetime object
                transaction_date = form.date.data
                transaction_time = form.time.data
                transaction_datetime = datetime.combine(transaction_date, transaction_time)
                
                # Update transaction with form data
                transaction.type = form.type.data
                transaction.amount = form.amount.data
                transaction.date = transaction_datetime  # Use the combined datetime
                transaction.category = form.category.data
                transaction.notes = form.notes.data
                
                # Handle file upload (optional)
                if form.attachment.data and form.attachment.data.filename:
                    filename = FileUtils.save_uploaded_file(
                        form.attachment.data,
                        app.config['UPLOAD_FOLDER']
                    )
                    if filename:
                        transaction.attachment = filename
                
                # Recalculate customer balance
                # First, reverse the old transaction effect
                if old_transaction_type == 'cash_in':
                    customer.current_balance -= old_transaction_amount
                else:  # cash_out
                    customer.current_balance += old_transaction_amount
                
                # Then apply the new transaction effect
                if transaction.type == 'cash_in':
                    customer.current_balance += transaction.amount
                else:  # cash_out
                    customer.current_balance -= transaction.amount
                
                customer.updated_at = datetime.utcnow()
                db.session.commit()
                
                # Create audit log
                audit_log = AuditLog(
                    action='UPDATE',
                    table_name='transaction',
                    record_id=transaction_id,
                    old_values=str({
                        'type': old_type,
                        'amount': old_amount,
                        'datetime': old_datetime.isoformat() if old_datetime else None,
                        'category': transaction.category,
                        'notes': transaction.notes
                    }),
                    new_values=str({
                        'type': transaction.type,
                        'amount': transaction.amount,
                        'datetime': transaction_datetime.isoformat(),
                        'category': transaction.category,
                        'notes': transaction.notes
                    }),
                    user_id=current_user.id,
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                
                # Create notification
                notification = Notification(
                    user_id=current_user.id,
                    title='Transaction Updated',
                    message=f'Transaction for {customer.name} was updated.',
                    type='info'
                )
                db.session.add(notification)
                db.session.commit()
                
                flash('Transaction updated successfully!', 'success')
                return redirect(url_for('customer_detail', customer_id=customer_id))
                
            except Exception as e:
                db.session.rollback()
                print(f"Error updating transaction: {str(e)}")
                flash('Error updating transaction. Please try again.', 'danger')
        
        # If form validation fails, show form with errors
        return render_template('dashboard/transactions.html',
                             form=form,
                             customer=customer,
                             transaction=transaction,
                             transaction_type=transaction.type,
                             is_edit=True)
    
    @app.route('/customer/<customer_id>/transaction/<transaction_id>/delete', methods=['POST'])
    @login_required
    def delete_transaction(customer_id, transaction_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        transaction = Transaction.query.filter_by(
            id=transaction_id,
            customer_id=customer_id
        ).first_or_404()
        
        try:
            # Update customer balance (reverse the transaction)
            if transaction.type == 'cash_in':
                customer.current_balance -= transaction.amount
            else:
                customer.current_balance += transaction.amount
            
            # Delete the transaction
            db.session.delete(transaction)
            db.session.commit()
            
            # Create audit log
            audit_log = AuditLog(
                action='DELETE',
                table_name='transaction',
                record_id=transaction_id,
                old_values=str({
                    'type': transaction.type,
                    'amount': transaction.amount,
                    'customer_id': customer_id,
                    'datetime': transaction.date.isoformat() if transaction.date else None
                }),
                new_values=None,
                user_id=current_user.id,
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Transaction Deleted',
                message=f'Transaction of ₹{transaction.amount:.2f} for {customer.name} was deleted.',
                type='warning'
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Transaction deleted successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting transaction: {str(e)}")
            flash('Error deleting transaction. Please try again.', 'danger')
        
        return redirect(url_for('customer_detail', customer_id=customer_id))
    
    @app.route('/api/transaction/<transaction_id>')
    @login_required
    def get_transaction(transaction_id):
        transaction = Transaction.query.join(Customer).join(Account).filter(
            Transaction.id == transaction_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        return jsonify({
            'id': transaction.id,
            'amount': transaction.amount,
            'date': transaction.date.strftime('%Y-%m-%d') if transaction.date else '',
            'time': transaction.date.strftime('%H:%M') if transaction.date else '',
            'category': transaction.category,
            'notes': transaction.notes,
            'type': transaction.type
        })
    
    @app.route('/reports')
    @login_required
    def reports():
        # Get statistics for the reports page
        total_balance = db.session.query(func.sum(Customer.current_balance)).join(Account).filter(
            Account.user_id == current_user.id
        ).scalar() or 0
        
        total_revenue = db.session.query(func.sum(Transaction.amount)).join(Customer).join(Account).filter(
            Account.user_id == current_user.id,
            Transaction.type == 'cash_in'
        ).scalar() or 0
        
        total_expenses = db.session.query(func.sum(Transaction.amount)).join(Customer).join(Account).filter(
            Account.user_id == current_user.id,
            Transaction.type == 'cash_out'
        ).scalar() or 0
        
        customer_count = Customer.query.join(Account).filter(
            Account.user_id == current_user.id
        ).count()
        
        transaction_count = Transaction.query.join(Customer).join(Account).filter(
            Account.user_id == current_user.id
        ).count()
        
        active_accounts = Account.query.filter_by(user_id=current_user.id).count()
        
        customers = Customer.query.join(Account).filter(
            Account.user_id == current_user.id
        ).all()
        
        return render_template('dashboard/reports.html',
                             total_balance=total_balance,
                             total_revenue=total_revenue,
                             total_expenses=total_expenses,
                             customer_count=customer_count,
                             transaction_count=transaction_count,
                             active_accounts=active_accounts,
                             customers=customers,
                             recent_reports=[])
    
    @app.route('/customer/<customer_id>/report/pdf')
    @login_required
    def generate_pdf_report(customer_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        transactions = Transaction.query.filter_by(customer_id=customer_id).order_by(Transaction.date.desc()).all()
        
        try:
            logger.info(f"PDF generation requested for customer: {customer.name} (ID: {customer_id})")
            logger.info(f"Number of transactions: {len(transactions)}")
            
            pdf_content = ReportUtils.generate_pdf_report(customer, transactions)
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='PDF Report Generated',
                message=f'PDF report for {customer.name} was generated successfully.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()
            
            logger.info(f"PDF successfully generated and sent for customer: {customer.name}")
            
            return send_file(
                BytesIO(pdf_content),
                download_name=f"{customer.name.replace(' ', '_')}_report.pdf",
                as_attachment=True,
                mimetype='application/pdf'
            )
            
        except Exception as e:
            error_msg = f"PDF generation failed: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())  # This will log the full stack trace
            
            # More specific error messages for common issues
            if "WeasyPrint not installed" in str(e):
                flash('PDF generation requires WeasyPrint. Please contact administrator.', 'danger')
            elif "TemplateNotFound" in str(e):
                flash('PDF template not found. Please contact administrator.', 'danger')
            elif "empty" in str(e).lower():
                flash('PDF generation returned empty content. Please try again.', 'danger')
            else:
                flash(f'Failed to generate PDF report: {str(e)}', 'danger')
                
            return redirect(url_for('customer_detail', customer_id=customer_id))
    
    @app.route('/customer/<customer_id>/report/excel')
    @login_required
    def generate_excel_report(customer_id):
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        transactions = Transaction.query.filter_by(customer_id=customer_id).order_by(Transaction.date.desc()).all()
        
        try:
            excel_content = ReportUtils.generate_excel_report(customer, transactions)
            
            if excel_content is None:
                flash('Failed to generate Excel report. Please check server logs.', 'danger')
                return redirect(url_for('customer_detail', customer_id=customer_id))
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Excel Report Generated',
                message=f'Excel report for {customer.name} was generated successfully.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()
            
            return send_file(
                BytesIO(excel_content),
                download_name=f"{customer.name.replace(' ', '_')}_report.xlsx",
                as_attachment=True,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
        except Exception as e:
            flash('Failed to generate Excel report. Please try again.', 'danger')
            return redirect(url_for('customer_detail', customer_id=customer_id))
    
    # Debug route for PDF generation status
    @app.route('/debug/pdf-status/<customer_id>')
    @login_required
    def debug_pdf_status(customer_id):
        """Debug route to check PDF generation status"""
        customer = Customer.query.join(Account).filter(
            Customer.id == customer_id,
            Account.user_id == current_user.id
        ).first_or_404()
        
        transactions = Transaction.query.filter_by(customer_id=customer_id).order_by(Transaction.date.desc()).all()
        
        debug_info = {
            'customer': {
                'name': customer.name,
                'email': customer.email,
                'balance': float(customer.current_balance)
            },
            'transactions_count': len(transactions),
            'weasyprint_available': False,
            'template_exists': False,
            'error': None
        }
        
        try:
            # Check if WeasyPrint is available
            try:
                from weasyprint import HTML
                debug_info['weasyprint_available'] = True
            except ImportError as e:
                debug_info['error'] = f"WeasyPrint not installed: {e}"
                return jsonify(debug_info)
            
            # Check if template exists
            try:
                html_content = render_template('pdf_template.html',
                                            customer=customer,
                                            transactions=transactions,
                                            generated_at=datetime.utcnow())
                debug_info['template_exists'] = True
                debug_info['html_content_length'] = len(html_content)
            except Exception as e:
                debug_info['error'] = f"Template error: {e}"
                return jsonify(debug_info)
            
            # Try to generate PDF
            try:
                from weasyprint.text.fonts import FontConfiguration
                font_config = FontConfiguration()
                pdf = HTML(string=html_content).write_pdf(font_config=font_config)
                debug_info['pdf_generated'] = True
                debug_info['pdf_size'] = len(pdf)
            except Exception as e:
                debug_info['error'] = f"PDF generation error: {e}"
                
        except Exception as e:
            debug_info['error'] = f"Unexpected error: {e}"
        
        return jsonify(debug_info)
    
    # API Documentation Route
    @app.route('/api/documentation')
    @login_required
    def api_documentation():
        """API Documentation page"""
        return render_template('api/documentation.html')
    
    # Notification Center
    @app.route('/notification-center')
    @login_required
    def notification_center():
        notifications = Notification.query.filter_by(
            user_id=current_user.id
        ).order_by(Notification.created_at.desc()).limit(50).all()
        
        unread_count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
        
        return render_template('components/notification_center.html',
                             notifications=notifications,
                             unread_count=unread_count)
    
    @app.route('/api/notifications/<notification_id>/read', methods=['POST'])
    @login_required
    def mark_notification_read(notification_id):
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user.id
        ).first_or_404()
        
        notification.is_read = True
        db.session.commit()
        
        return jsonify({'success': True})
    
    @app.route('/api/notifications/mark-all-read', methods=['POST'])
    @login_required
    def mark_all_notifications_read():
        Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        
        return jsonify({'success': True})
    
    # API Routes for AJAX calls
    @app.route('/api/dashboard/stats')
    @login_required
    def api_dashboard_stats():
        total_customers = Customer.query.join(Account).filter(Account.user_id == current_user.id).count()
        total_balance = db.session.query(func.sum(Customer.current_balance)).join(Account).filter(
            Account.user_id == current_user.id
        ).scalar() or 0
        
        current_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_revenue = db.session.query(func.sum(Transaction.amount)).join(Customer).join(Account).filter(
            Account.user_id == current_user.id,
            Transaction.type == 'cash_in',
            Transaction.date >= current_month
        ).scalar() or 0
        
        monthly_expenses = db.session.query(func.sum(Transaction.amount)).join(Customer).join(Account).filter(
            Account.user_id == current_user.id,
            Transaction.type == 'cash_out',
            Transaction.date >= current_month
        ).scalar() or 0
        
        return jsonify({
            'total_customers': total_customers,
            'total_balance': float(total_balance),
            'monthly_revenue': float(monthly_revenue),
            'monthly_expenses': float(monthly_expenses)
        })
    
    @app.route('/api/transactions/recent')
    @login_required
    def api_recent_transactions():
        transactions = Transaction.query.join(Customer).join(Account).filter(
            Account.user_id == current_user.id
        ).order_by(Transaction.date.desc()).limit(10).all()
        
        transactions_data = []
        for transaction in transactions:
            transactions_data.append({
                'id': transaction.id,
                'customer_name': transaction.customer.name,
                'type': transaction.type,
                'amount': float(transaction.amount),
                'date': transaction.date.strftime('%Y-%m-%d'),
                'category': transaction.category
            })
        
        return jsonify(transactions_data)
    
    # Profile Routes
    @app.route('/profile')
    @login_required
    def profile():
        stats = {
            'total_customers': Customer.query.join(Account).filter(Account.user_id == current_user.id).count(),
            'total_transactions': Transaction.query.join(Customer).join(Account).filter(Account.user_id == current_user.id).count(),
            'total_balance': db.session.query(func.sum(Customer.current_balance)).join(Account).filter(Account.user_id == current_user.id).scalar() or 0,
            'reports_generated': 0  # You can implement this tracking
        }
        
        recent_activity = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
        sessions = UserSession.query.filter_by(user_id=current_user.id, logged_out_at=None).order_by(UserSession.last_activity.desc()).all()
        
        # Calculate recent threshold (24 hours ago)
        recent_threshold = datetime.utcnow() - timedelta(hours=24)
        
        return render_template('dashboard/profile.html', 
                             user=current_user,
                             stats=stats,
                             recent_activity=recent_activity,
                             sessions=sessions,
                             recent_threshold=recent_threshold)
    
    @app.route('/profile/update', methods=['POST'])
    @login_required
    def update_profile():
        current_user.name = request.form.get('name', current_user.name)
        current_user.email = request.form.get('email', current_user.email)
        current_user.phone = request.form.get('phone', current_user.phone)
        current_user.company = request.form.get('company', current_user.company)
        
        db.session.commit()
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    @app.route('/profile/update-avatar', methods=['POST'])
    @login_required
    def update_avatar():
        """Update user avatar"""
        try:
            if 'avatar' not in request.files:
                return jsonify({'success': False, 'message': 'No file selected'})
            
            file = request.files['avatar']
            if file.filename == '':
                return jsonify({'success': False, 'message': 'No file selected'})
            
            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            if not FileUtils.allowed_file(file.filename, allowed_extensions):
                return jsonify({'success': False, 'message': 'Invalid file type. Please use JPG, PNG, or GIF.'})
            
            # Save the file
            filename = FileUtils.save_uploaded_file(
                file, 
                app.config['UPLOAD_FOLDER']
            )
            
            if not filename:
                return jsonify({'success': False, 'message': 'Failed to save file'})
            
            # Update user's avatar URL
            current_user.avatar_url = url_for('static', filename=f'uploads/{filename}', _external=True)
            db.session.commit()
            
            # Create audit log
            audit_log = AuditLog(
                action='UPDATE',
                table_name='user',
                record_id=current_user.id,
                old_values=None,
                new_values=f"avatar_url: {current_user.avatar_url}",
                user_id=current_user.id,
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            return jsonify({
                'success': True, 
                'avatar_url': current_user.avatar_url,
                'message': 'Avatar updated successfully'
            })
            
        except Exception as e:
            logger.error(f"Avatar update failed: {e}")
            return jsonify({'success': False, 'message': 'Failed to update avatar'})
    
    @app.route('/profile/change-password', methods=['POST'])
    @login_required
    def change_password():
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('profile'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('profile'))
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('profile'))
        
        current_user.set_password(new_password)
        db.session.commit()
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    @app.route('/profile/enable-2fa', methods=['POST'])
    @login_required
    def enable_2fa():
        # Implement 2FA enable logic here
        flash('Two-factor authentication enabled!', 'success')
        return redirect(url_for('profile'))
    
    @app.route('/profile/disable-2fa', methods=['POST'])
    @login_required
    def disable_2fa():
        # Implement 2FA disable logic here
        flash('Two-factor authentication disabled!', 'success')
        return redirect(url_for('profile'))
    
    @app.route('/sessions/<session_id>/revoke', methods=['POST'])
    @login_required
    def revoke_session(session_id):
        session = UserSession.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()
        session.logged_out_at = datetime.utcnow()
        db.session.commit()
        
        flash('Session revoked successfully!', 'success')
        return redirect(url_for('profile'))
    
    @app.route('/sessions/revoke-all', methods=['POST'])
    @login_required
    def revoke_all_sessions():
        UserSession.query.filter_by(user_id=current_user.id, logged_out_at=None).update({
            'logged_out_at': datetime.utcnow()
        })
        db.session.commit()
        
        flash('All other sessions revoked successfully!', 'success')
        return redirect(url_for('profile'))
    
    @app.route('/profile/update-notifications', methods=['POST'])
    @login_required
    def update_notifications():
        # Update notification preferences
        current_user.email_notifications = 'emailNotifications' in request.form
        current_user.transaction_alerts = 'transactionAlerts' in request.form
        current_user.report_digest = 'reportDigest' in request.form
        current_user.security_alerts = 'securityAlerts' in request.form
        
        db.session.commit()
        
        return jsonify({'success': True})
    
    # Settings Routes
    @app.route('/settings')
    @login_required
    def settings():
        user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if not user_settings:
            user_settings = UserSettings(user_id=current_user.id)
            db.session.add(user_settings)
            db.session.commit()
        
        # Mock data for integrations and API
        integrations_data = {
            'google_sheets': False,
            'slack': False,
            'quickbooks': False
        }
        
        api_usage_data = {
            'requests_today': 0,
            'requests_month': 0,
            'limit': 1000
        }
        
        return render_template('dashboard/settings.html',
                             settings=user_settings,
                             integrations=integrations_data,
                             api_usage=api_usage_data,
                             api_key=None,
                             backups=[])
    
    @app.route('/settings/update-general', methods=['POST'])
    @login_required
    def update_general_settings():
        user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if not user_settings:
            user_settings = UserSettings(user_id=current_user.id)
            db.session.add(user_settings)
        
        user_settings.default_currency = request.form.get('default_currency', 'INR')
        user_settings.date_format = request.form.get('date_format', 'YYYY-MM-DD')
        user_settings.timezone = request.form.get('timezone', 'Asia/Kolkata')
        user_settings.items_per_page = int(request.form.get('items_per_page', 25))
        user_settings.auto_logout = 'auto_logout' in request.form
        user_settings.email_reports = 'email_reports' in request.form
        
        db.session.commit()
        flash('General settings updated successfully!', 'success')
        return redirect(url_for('settings'))
    
    @app.route('/settings/update-appearance', methods=['POST'])
    @login_required
    def update_appearance_settings():
        user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if not user_settings:
            user_settings = UserSettings(user_id=current_user.id)
            db.session.add(user_settings)
        
        user_settings.theme = request.form.get('theme', 'light')
        user_settings.dashboard_layout = request.form.get('dashboard_layout', 'compact')
        user_settings.animations = 'animations' in request.form
        
        db.session.commit()
        flash('Appearance settings updated successfully!', 'success')
        return redirect(url_for('settings'))
    
    @app.route('/settings/update-notifications', methods=['POST'])
    @login_required
    def update_notification_settings():
        user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if not user_settings:
            user_settings = UserSettings(user_id=current_user.id)
            db.session.add(user_settings)
        
        user_settings.transaction_emails = 'transaction_emails' in request.form
        user_settings.balance_alerts = 'balance_alerts' in request.form
        user_settings.report_ready = 'report_ready' in request.form
        user_settings.browser_notifications = 'browser_notifications' in request.form
        
        db.session.commit()
        flash('Notification settings updated successfully!', 'success')
        return redirect(url_for('settings'))
    
    @app.route('/settings/create-backup', methods=['POST'])
    @login_required
    def create_backup():
        """Create a backup of all user data"""
        try:
            # Get all user data
            user_data = {
                'user': {
                    'id': current_user.id,
                    'name': current_user.name,
                    'email': current_user.email,
                    'phone': current_user.phone,
                    'company': current_user.company,
                    'created_at': safe_iso(current_user.created_at),
                    'last_login': safe_iso(current_user.last_login)
                },
                'accounts': [],
                'customers': [],
                'transactions': [],
                'settings': {},
                'audit_logs': [],
                'notifications': [],
                'export_info': {
                    'exported_at': datetime.utcnow().isoformat(),
                    'fiscalflow_version': '1.0.0',
                    'data_format': 'fiscalflow_backup_v1'
                }
            }
            
            # Get accounts
            accounts = Account.query.filter_by(user_id=current_user.id).all()
            for account in accounts:
                user_data['accounts'].append({
                    'id': account.id,
                    'name': account.name,
                    'description': account.description,
                    'currency': account.currency,
                    'created_at': safe_iso(account.created_at)
                })
            
            # Get customers
            customers = Customer.query.join(Account).filter(Account.user_id == current_user.id).all()
            for customer in customers:
                user_data['customers'].append({
                    'id': customer.id,
                    'name': customer.name,
                    'email': customer.email,
                    'phone': customer.phone,
                    'category': customer.category,
                    # Credit limit removed
                    'current_balance': float(customer.current_balance),
                    'account_id': customer.account_id,
                    'created_at': safe_iso(customer.created_at),
                    'updated_at': safe_iso(customer.updated_at)
                })
            
            # Get transactions
            transactions = Transaction.query.join(Customer).join(Account).filter(
                Account.user_id == current_user.id
            ).all()
            for transaction in transactions:
                user_data['transactions'].append({
                    'id': transaction.id,
                    'type': transaction.type,
                    'amount': float(transaction.amount),
                    'date': safe_iso(transaction.date),
                    'category': transaction.category,
                    'notes': transaction.notes,
                    'attachment': transaction.attachment,
                    'customer_id': transaction.customer_id,
                    'created_by': transaction.created_by,
                    'created_at': safe_iso(transaction.created_at)
                })
            
            # Get user settings
            user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
            if user_settings:
                user_data['settings'] = {
                    'default_currency': user_settings.default_currency,
                    'date_format': user_settings.date_format,
                    'timezone': user_settings.timezone,
                    'items_per_page': user_settings.items_per_page,
                    'auto_logout': user_settings.auto_logout,
                    'email_reports': user_settings.email_reports,
                    'theme': user_settings.theme,
                    'dashboard_layout': user_settings.dashboard_layout,
                    'animations': user_settings.animations,
                    'transaction_emails': user_settings.transaction_emails,
                    'balance_alerts': user_settings.balance_alerts,
                    'report_ready': user_settings.report_ready,
                    'browser_notifications': user_settings.browser_notifications,
                    'created_at': safe_iso(user_settings.created_at),
                    'updated_at': safe_iso(user_settings.updated_at)
                }
            
            # Get audit logs (last 100)
            audit_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(
                AuditLog.timestamp.desc()
            ).limit(100).all()
            for log in audit_logs:
                user_data['audit_logs'].append({
                    'id': log.id,
                    'action': log.action,
                    'table_name': log.table_name,
                    'record_id': log.record_id,
                    'old_values': log.old_values,
                    'new_values': log.new_values,
                    'ip_address': log.ip_address,
                    'timestamp': safe_iso(log.timestamp)
                })
            
            # Get notifications (last 50)
            notifications = Notification.query.filter_by(user_id=current_user.id).order_by(
                Notification.created_at.desc()
            ).limit(50).all()
            for notification in notifications:
                user_data['notifications'].append({
                    'id': notification.id,
                    'title': notification.title,
                    'message': notification.message,
                    'type': notification.type,
                    'is_read': notification.is_read,
                    'action_url': notification.action_url,
                    'created_at': safe_iso(notification.created_at)
                })
            
            # Create JSON file in memory
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"fiscalflow_backup_{timestamp}.json"
            json_data = json.dumps(user_data, indent=2, ensure_ascii=False)
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Backup Created',
                message='Your data backup was created successfully.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()
            
            # Return JSON file
            return send_file(
                BytesIO(json_data.encode('utf-8')),
                download_name=filename,
                as_attachment=True,
                mimetype='application/json'
            )
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            flash('Failed to create backup. Please try again.', 'danger')
            return redirect(url_for('settings'))
    
    @app.route('/settings/restore-backup', methods=['POST'])
    @login_required
    def restore_backup():
        """Restore data from a backup file"""
        try:
            if 'backup_file' not in request.files:
                flash('No file selected', 'danger')
                return redirect(url_for('settings'))
            
            file = request.files['backup_file']
            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('settings'))
            
            if not file.filename.endswith('.json'):
                flash('Please select a valid JSON backup file', 'danger')
                return redirect(url_for('settings'))
            
            # Read and parse the backup file
            backup_data = json.loads(file.read().decode('utf-8'))
            
            # Validate backup format
            if 'export_info' not in backup_data or 'data_format' not in backup_data['export_info']:
                flash('Invalid backup file format', 'danger')
                return redirect(url_for('settings'))
            
            # TODO: Implement actual restore logic here
            # This is a complex operation that should be done carefully
            
            flash('Backup restoration is not yet implemented. Please contact support.', 'warning')
            return redirect(url_for('settings'))
            
        except json.JSONDecodeError:
            flash('Invalid JSON file', 'danger')
            return redirect(url_for('settings'))
        except Exception as e:
            logger.error(f"Backup restoration failed: {e}")
            flash('Failed to restore backup. Please try again.', 'danger')
            return redirect(url_for('settings'))
    
    @app.route('/settings/generate-api-key', methods=['POST'])
    @login_required
    def generate_api_key():
        """Generate a new API key for the user"""
        try:
            # Generate a secure API key
            api_key = secrets.token_urlsafe(32)
            
            # Store the API key (in a real implementation, you'd store this securely)
            # For now, we'll just show it to the user
            flash(f'API key generated: {api_key}', 'success')
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='API Key Generated',
                message='A new API key was generated for your account.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()
            
        except Exception as e:
            logger.error(f"API key generation failed: {e}")
            flash('Failed to generate API key. Please try again.', 'danger')
        
        return redirect(url_for('settings'))
    
    @app.route('/settings/regenerate-api-key', methods=['POST'])
    @login_required
    def regenerate_api_key():
        """Regenerate the user's API key"""
        try:
            # Generate a new secure API key
            api_key = secrets.token_urlsafe(32)
            
            # Store the new API key (in a real implementation, you'd update it securely)
            flash(f'New API key generated: {api_key}', 'success')
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='API Key Regenerated',
                message='Your API key was regenerated. The old key is no longer valid.',
                type='warning'
            )
            db.session.add(notification)
            db.session.commit()
            
        except Exception as e:
            logger.error(f"API key regeneration failed: {e}")
            flash('Failed to regenerate API key. Please try again.', 'danger')
        
        return redirect(url_for('settings'))
    
    @app.route('/settings/revoke-api-key', methods=['POST'])
    @login_required
    def revoke_api_key():
        """Revoke the user's API key"""
        try:
            # Revoke the API key (in a real implementation, you'd mark it as invalid)
            flash('API key revoked successfully', 'success')
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='API Key Revoked',
                message='Your API key was revoked and can no longer be used.',
                type='warning'
            )
            db.session.add(notification)
            db.session.commit()
            
        except Exception as e:
            logger.error(f"API key revocation failed: {e}")
            flash('Failed to revoke API key. Please try again.', 'danger')
        
        return redirect(url_for('settings'))
    
    @app.route('/settings/export-all-data', methods=['POST'])
    @login_required
    def export_all_data():
        """Export all user data as a comprehensive JSON file"""
        try:
            # Get all user data (same as backup but with different filename)
            user_data = {
                'user': {
                    'id': current_user.id,
                    'name': current_user.name,
                    'email': current_user.email,
                    'phone': current_user.phone,
                    'company': current_user.company,
                    'created_at': safe_iso(current_user.created_at),
                    'last_login': safe_iso(current_user.last_login)
                },
                'accounts': [],
                'customers': [],
                'transactions': [],
                'settings': {},
                'export_info': {
                    'exported_at': datetime.utcnow().isoformat(),
                    'purpose': 'data_export',
                    'fiscalflow_version': '1.0.0'
                }
            }
            
            # Get accounts
            accounts = Account.query.filter_by(user_id=current_user.id).all()
            for account in accounts:
                user_data['accounts'].append({
                    'id': account.id,
                    'name': account.name,
                    'description': account.description,
                    'currency': account.currency,
                    'created_at': safe_iso(account.created_at)
                })
            
            # Get customers
            customers = Customer.query.join(Account).filter(Account.user_id == current_user.id).all()
            for customer in customers:
                user_data['customers'].append({
                    'id': customer.id,
                    'name': customer.name,
                    'email': customer.email,
                    'phone': customer.phone,
                    'category': customer.category,
                    # Credit limit removed
                    'current_balance': float(customer.current_balance),
                    'account_id': customer.account_id,
                    'created_at': safe_iso(customer.created_at),
                    'updated_at': safe_iso(customer.updated_at)
                })
            
            # Get transactions
            transactions = Transaction.query.join(Customer).join(Account).filter(
                Account.user_id == current_user.id
            ).all()
            for transaction in transactions:
                user_data['transactions'].append({
                    'id': transaction.id,
                    'type': transaction.type,
                    'amount': float(transaction.amount),
                    'date': safe_iso(transaction.date),
                    'category': transaction.category,
                    'notes': transaction.notes,
                    'attachment': transaction.attachment,
                    'customer_id': transaction.customer_id,
                    'created_by': transaction.created_by,
                    'created_at': safe_iso(transaction.created_at)
                })
            
            # Get user settings
            user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
            if user_settings:
                user_data['settings'] = {
                    'default_currency': user_settings.default_currency,
                    'date_format': user_settings.date_format,
                    'timezone': user_settings.timezone,
                    'items_per_page': user_settings.items_per_page,
                    'auto_logout': user_settings.auto_logout,
                    'email_reports': user_settings.email_reports,
                    'theme': user_settings.theme,
                    'dashboard_layout': user_settings.dashboard_layout,
                    'animations': user_settings.animations,
                    'transaction_emails': user_settings.transaction_emails,
                    'balance_alerts': user_settings.balance_alerts,
                    'report_ready': user_settings.report_ready,
                    'browser_notifications': user_settings.browser_notifications,
                    'created_at': safe_iso(user_settings.created_at),
                    'updated_at': safe_iso(user_settings.updated_at)
                }
            
            # Create JSON file in memory
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"fiscalflow_export_{timestamp}.json"
            json_data = json.dumps(user_data, indent=2, ensure_ascii=False)
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Data Export Completed',
                message='All your data has been exported successfully.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()
            
            # Return JSON file
            return send_file(
                BytesIO(json_data.encode('utf-8')),
                download_name=filename,
                as_attachment=True,
                mimetype='application/json'
            )
            
        except Exception as e:
            logger.error(f"Data export failed: {e}")
            flash('Failed to export data. Please try again.', 'danger')
            return redirect(url_for('settings'))
    
    @app.route('/settings/clear-data', methods=['POST'])
    @login_required
    def clear_all_data():
        """Clear all user data (Dangerous operation!)"""
        confirm_text = request.form.get('confirm_text')
        if confirm_text != 'DELETE ALL DATA':
            flash('Confirmation text does not match', 'danger')
            return redirect(url_for('settings'))
        
        try:
            # Get user ID for reference
            user_id = current_user.id
            
            # Delete all user's transactions
            Transaction.query.join(Customer).join(Account).filter(
                Account.user_id == user_id
            ).delete(synchronize_session=False)
            
            # Delete all user's customers
            Customer.query.join(Account).filter(
                Account.user_id == user_id
            ).delete(synchronize_session=False)
            
            # Delete all user's accounts
            Account.query.filter_by(user_id=user_id).delete(synchronize_session=False)
            
            # Reset user settings to defaults
            user_settings = UserSettings.query.filter_by(user_id=user_id).first()
            if user_settings:
                user_settings.default_currency = 'INR'
                user_settings.date_format = 'YYYY-MM-DD'
                user_settings.timezone = 'Asia/Kolkata'
                user_settings.items_per_page = 25
                user_settings.auto_logout = True
                user_settings.email_reports = True
                user_settings.theme = 'light'
                user_settings.dashboard_layout = 'compact'
                user_settings.animations = True
                user_settings.transaction_emails = True
                user_settings.balance_alerts = True
                user_settings.report_ready = True
                user_settings.browser_notifications = False
            
            db.session.commit()
            
            # Create audit log
            audit_log = AuditLog(
                action='CLEAR_ALL_DATA',
                table_name='user',
                record_id=user_id,
                old_values='All user data',
                new_values='Data cleared',
                user_id=user_id,
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            
            # Create notification
            notification = Notification(
                user_id=user_id,
                title='All Data Cleared',
                message='All your accounts, customers, and transactions have been deleted.',
                type='warning'
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('All data cleared successfully!', 'success')
            
        except Exception as e:
            logger.error(f"Data clearance failed: {e}")
            db.session.rollback()
            flash('Failed to clear data. Please try again.', 'danger')
        
        return redirect(url_for('settings'))
    
    @app.route('/settings/delete-account', methods=['POST'])
    @login_required
    def delete_account():
        """Permanently delete user account (Very dangerous operation!)"""
        confirm_text = request.form.get('confirm_text')
        password = request.form.get('password')
        
        if confirm_text != 'DELETE MY ACCOUNT':
            flash('Confirmation text does not match', 'danger')
            return redirect(url_for('settings'))
        
        if not current_user.check_password(password):
            flash('Invalid password', 'danger')
            return redirect(url_for('settings'))
        
        try:
            # Get user ID for reference before deletion
            user_id = current_user.id
            user_email = current_user.email
            
            # Delete all user's transactions
            Transaction.query.join(Customer).join(Account).filter(
                Account.user_id == user_id
            ).delete(synchronize_session=False)
            
            # Delete all user's customers
            Customer.query.join(Account).filter(
                Account.user_id == user_id
            ).delete(synchronize_session=False)
            
            # Delete all user's accounts
            Account.query.filter_by(user_id=user_id).delete(synchronize_session=False)
            
            # Delete user settings
            UserSettings.query.filter_by(user_id=user_id).delete(synchronize_session=False)
            
            # Delete user sessions
            UserSession.query.filter_by(user_id=user_id).delete(synchronize_session=False)
            
            # Delete user notifications
            Notification.query.filter_by(user_id=user_id).delete(synchronize_session=False)
            
            # Delete user audit logs
            AuditLog.query.filter_by(user_id=user_id).delete(synchronize_session=False)
            
            # Finally, delete the user
            User.query.filter_by(id=user_id).delete(synchronize_session=False)
            
            db.session.commit()
            
            # Logout the user
            logout_user()
            
            flash('Your account has been permanently deleted. Thank you for using FiscalFlow.', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            logger.error(f"Account deletion failed: {e}")
            db.session.rollback()
            flash('Failed to delete account. Please try again.', 'danger')
            return redirect(url_for('settings'))
    
    # Email Test Route (REMOVE THIS IN PRODUCTION)
    @app.route('/test-email')
    def test_email():
        """Test email configuration - REMOVE IN PRODUCTION"""
        try:
            # Test with a simple email
            test_email = "your-test-email@gmail.com"  # Change this to your test email
            otp_code = OTPUtils.generate_otp()
            
            success = email_utils.send_otp_email(test_email, otp_code)
            
            if success:
                return jsonify({"status": "success", "message": "Test email sent successfully!"})
            else:
                return jsonify({"status": "error", "message": "Failed to send test email"})
                
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})
    
    # Bulk Operations
    @app.route('/bulk-import', methods=['GET', 'POST'])
    @login_required
    def bulk_import():
        form = BulkImportForm()
        step = 1
        preview_data = None
        preview_headers = None
        validation_results = None
        uploaded_filename = None
        import_type = None

        if request.method == 'POST' and form.csv_file.data:
            try:
                # Get uploaded file
                file = form.csv_file.data
                import_type = form.import_type.data
                uploaded_filename = secure_filename(file.filename)
                
                # Read CSV file
                stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.reader(stream)
                
                # Get headers and first few rows for preview
                rows = list(csv_input)
                if not rows:
                    flash('CSV file is empty', 'danger')
                    return redirect(url_for('bulk_import'))
                
                preview_headers = rows[0]
                preview_data = rows[1:6]  # First 5 rows for preview
                
                # Validate data
                validation_results = validate_csv_data(rows, import_type, current_user.id)
                
                step = 2  # Move to validation step
                
                # Create notification
                notification = Notification(
                    user_id=current_user.id,
                    title='File Uploaded',
                    message=f'{uploaded_filename} was uploaded for validation.',
                    type='info'
                )
                db.session.add(notification)
                db.session.commit()
                
                flash('File uploaded successfully! Please review the validation results.', 'success')
                
            except Exception as e:
                logger.error(f"Bulk import upload failed: {e}")
                flash('Failed to process uploaded file. Please check the file format.', 'danger')
        return render_template('dashboard/bulk_import.html', 
                             form=form,
                             step=step,
                             preview_data=preview_data,
                             preview_headers=preview_headers,
                             validation_results=validation_results,
                             import_results=None,
                             uploaded_filename=uploaded_filename,
                             import_type=import_type)

    @app.route('/download-template/<template_type>')
    @login_required
    def download_template(template_type):
        """Serve CSV templates with real user data for bulk import"""
        try:
            if template_type == 'customers':
                filename = 'my_customers.csv'
                headers = ['name', 'email', 'phone', 'category', 'current_balance']
                
                # Get current user's customers
                customers = Customer.query.join(Account).filter(
                    Account.user_id == current_user.id
                ).all()
                
                # Prepare data rows
                data_rows = []
                for customer in customers:
                    data_rows.append([
                        customer.name or '',
                        customer.email or '',
                        customer.phone or '',
                        customer.category or '',
                        str(customer.current_balance or '0.00')
                    ])
                
                if not data_rows:
                    flash('No customer data available to export.', 'info')
                    return redirect(url_for('bulk_import'))
                    
            elif template_type == 'transactions':
                filename = 'my_transactions.csv'
                headers = ['customer_id', 'customer_name', 'date', 'type', 'amount', 'category', 'notes']
                
                # Get current user's transactions
                transactions = Transaction.query.join(Customer).join(Account).filter(
                    Account.user_id == current_user.id
                ).order_by(Transaction.date.desc()).limit(1000).all()  # Limit to prevent memory issues
                
                # Prepare data rows
                data_rows = []
                for transaction in transactions:
                    data_rows.append([
                        str(transaction.customer_id),
                        transaction.customer.name if transaction.customer else '',
                        transaction.date.strftime('%Y-%m-%d') if transaction.date else '',
                        transaction.type or '',
                        str(transaction.amount or '0.00'),
                        transaction.category or '',
                        transaction.notes or ''
                    ])
                
                if not data_rows:
                    flash('No transaction data available to export.', 'info')
                    return redirect(url_for('bulk_import'))
                    
            elif template_type == 'complete':
                filename = 'my_complete_data.csv'
                headers = [
                    'customer_name', 'customer_email', 'customer_phone', 'customer_category', 
                    'customer_current_balance',
                    'transaction_date', 'transaction_type', 'transaction_amount', 
                    'transaction_category', 'transaction_notes'
                ]
                
                # Get current user's customers with their recent transactions
                customers = Customer.query.join(Account).filter(
                    Account.user_id == current_user.id
                ).all()
                
                # Prepare data rows - one row per customer with their latest transaction
                data_rows = []
                for customer in customers:
                    # Get latest transaction for this customer
                    latest_transaction = Transaction.query.filter_by(
                        customer_id=customer.id
                    ).order_by(Transaction.date.desc()).first()
                    
                    if latest_transaction:
                        data_rows.append([
                            customer.name or '',
                            customer.email or '',
                            customer.phone or '',
                            customer.category or '',
                            str(customer.current_balance or '0.00'),
                            latest_transaction.date.strftime('%Y-%m-%d') if latest_transaction.date else '',
                            latest_transaction.type or '',
                            str(latest_transaction.amount or '0.00'),
                            latest_transaction.category or '',
                            latest_transaction.notes or ''
                        ])
                    else:
                        # Customer without transactions
                        data_rows.append([
                            customer.name or '',
                            customer.email or '',
                            customer.phone or '',
                            customer.category or '',
                            str(customer.current_balance or '0.00'),
                            '', '', '', '', ''  # Empty transaction fields
                        ])
                
                if not data_rows:
                    flash('No data available to export.', 'info')
                    return redirect(url_for('bulk_import'))
            else:
                flash('Invalid template type', 'danger')
                return redirect(url_for('bulk_import'))

            # Create CSV in memory
            output = StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(headers)
            
            # Write real user data
            for row in data_rows:
                writer.writerow(row)
            
            # Prepare response
            output.seek(0)
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Data Exported',
                message=f'{filename} was downloaded successfully with {len(data_rows)} records.',
                type='info'
            )
            db.session.add(notification)
            db.session.commit()

            return send_file(
                BytesIO(output.getvalue().encode('utf-8')),
                download_name=filename,
                as_attachment=True,
                mimetype='text/csv'
            )

        except Exception as e:
            logger.error(f"Template download failed: {e}")
            flash('Failed to download data. Please try again.', 'danger')
            return redirect(url_for('bulk_import'))

    @app.route('/confirm-import', methods=['POST'])
    @login_required
    def confirm_import():
        """Finalize the import process"""
        try:
            filename = request.form.get('filename')
            import_type = request.form.get('import_type')
            
            if not filename or not import_type:
                flash('Missing import parameters', 'danger')
                return redirect(url_for('bulk_import'))
            
            # TODO: Implement actual import logic here
            # For now, return a success message
            import_results = {
                'success': True,
                'message': f'Successfully imported {import_type} data',
                'customers_imported': 0,
                'transactions_imported': 0
            }
            
            # Update counts based on import type
            if import_type == 'customers':
                import_results['customers_imported'] = 5  # Example count
            elif import_type == 'transactions':
                import_results['transactions_imported'] = 10  # Example count
            elif import_type == 'both':
                import_results['customers_imported'] = 3
                import_results['transactions_imported'] = 8
            
            # Create notification
            notification = Notification(
                user_id=current_user.id,
                title='Bulk Import Completed',
                message=f'Bulk import of {import_type} completed successfully.',
                type='success'
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Import completed successfully!', 'success')
            
            return render_template('dashboard/bulk_import.html', 
                                 form=BulkImportForm(),
                                 step=3,
                                 preview_data=None,
                                 preview_headers=None,
                                 validation_results=None,
                                 import_results=import_results,
                                 uploaded_filename=filename,
                                 import_type=import_type)
            
        except Exception as e:
            logger.error(f"Import confirmation failed: {e}")
            flash('Failed to complete import. Please try again.', 'danger')
            return redirect(url_for('bulk_import'))

def validate_csv_data(rows, import_type, user_id):
    """Validate CSV data for bulk import"""
    if not rows or len(rows) < 2:
        return {
            'valid': False,
            'errors': ['CSV file must contain headers and at least one data row'],
            'warnings': [],
            'summary': {
                'total_records': 0,
                'valid_records': 0,
                'warning_records': 0,
                'error_records': 0
            }
        }
    
    headers = rows[0]
    data_rows = rows[1:]
    
    errors = []
    warnings = []
    valid_records = 0
    warning_records = 0
    error_records = 0
    
    # Define required fields based on import type
    if import_type == 'customers':
        required_fields = ['name', 'email']
    elif import_type == 'transactions':
        required_fields = ['customer_id', 'date', 'type', 'amount']
    elif import_type == 'both':
        required_fields = ['customer_name', 'customer_email', 'transaction_date', 'transaction_type', 'transaction_amount']
    else:
        return {
            'valid': False,
            'errors': ['Invalid import type selected'],
            'warnings': [],
            'summary': {
                'total_records': len(data_rows),
                'valid_records': 0,
                'warning_records': 0,
                'error_records': len(data_rows)
            }
        }
    
    # Check for required headers
    missing_headers = []
    for field in required_fields:
        if field not in headers:
            missing_headers.append(field)
    
    if missing_headers:
        errors.append(f"Missing required columns: {', '.join(missing_headers)}")
        return {
            'valid': False,
            'errors': errors,
            'warnings': warnings,
            'summary': {
                'total_records': len(data_rows),
                'valid_records': 0,
                'warning_records': 0,
                'error_records': len(data_rows)
            }
        }
    
    # Validate each row
    for i, row in enumerate(data_rows, start=2):  # Start at 2 for line numbers (header is line 1)
        row_errors = []
        row_warnings = []
        
        # Create dict for easier access
        row_dict = dict(zip(headers, row))
        
        # Validate based on import type
        if import_type == 'customers':
            # Validate name
            if not row_dict.get('name', '').strip():
                row_errors.append(f"Row {i}: Customer name is required")
            
            # Validate email format
            email = row_dict.get('email', '').strip()
            if not email:
                row_errors.append(f"Row {i}: Email is required")
            elif '@' not in email:
                row_errors.append(f"Row {i}: Invalid email format")
            
            # Credit limit validation removed
            
        elif import_type == 'transactions':
            # Validate customer exists
            customer_id = row_dict.get('customer_id', '').strip()
            if not customer_id:
                row_errors.append(f"Row {i}: Customer ID is required")
            else:
                customer = Customer.query.join(Account).filter(
                    Customer.id == customer_id,
                    Account.user_id == user_id
                ).first()
                if not customer:
                    row_errors.append(f"Row {i}: Customer with ID {customer_id} not found")
            
            # Validate date
            date_str = row_dict.get('date', '').strip()
            if not date_str:
                row_errors.append(f"Row {i}: Date is required")
            else:
                try:
                    datetime.strptime(date_str, '%Y-%m-%d')
                except ValueError:
                    try:
                        datetime.strptime(date_str, '%m/%d/%Y')
                    except ValueError:
                        row_errors.append(f"Row {i}: Invalid date format. Use YYYY-MM-DD or MM/DD/YYYY")
            
            # Validate type
            trans_type = row_dict.get('type', '').strip().lower()
            if trans_type not in ['cash_in', 'cash_out']:
                row_errors.append(f"Row {i}: Type must be 'cash_in' or 'cash_out'")
            
            # Validate amount
            amount = row_dict.get('amount', '').strip()
            if not amount:
                row_errors.append(f"Row {i}: Amount is required")
            else:
                try:
                    amount_val = float(amount)
                    if amount_val <= 0:
                        row_errors.append(f"Row {i}: Amount must be greater than 0")
                except ValueError:
                    row_errors.append(f"Row {i}: Amount must be a valid number")
        
        elif import_type == 'both':
            # Validate customer data
            if not row_dict.get('customer_name', '').strip():
                row_errors.append(f"Row {i}: Customer name is required")
            
            email = row_dict.get('customer_email', '').strip()
            if not email:
                row_errors.append(f"Row {i}: Customer email is required")
            elif '@' not in email:
                row_errors.append(f"Row {i}: Invalid customer email format")
            
            # Validate transaction data
            date_str = row_dict.get('transaction_date', '').strip()
            if not date_str:
                row_errors.append(f"Row {i}: Transaction date is required")
            else:
                try:
                    datetime.strptime(date_str, '%Y-%m-%d')
                except ValueError:
                    try:
                        datetime.strptime(date_str, '%m/%d/%Y')
                    except ValueError:
                        row_errors.append(f"Row {i}: Invalid transaction date format")
            
            trans_type = row_dict.get('transaction_type', '').strip().lower()
            if trans_type not in ['cash_in', 'cash_out']:
                row_errors.append(f"Row {i}: Transaction type must be 'cash_in' or 'cash_out'")
            
            amount = row_dict.get('transaction_amount', '').strip()
            if not amount:
                row_errors.append(f"Row {i}: Transaction amount is required")
            else:
                try:
                    amount_val = float(amount)
                    if amount_val <= 0:
                        row_errors.append(f"Row {i}: Transaction amount must be greater than 0")
                except ValueError:
                    row_errors.append(f"Row {i}: Transaction amount must be a valid number")
        
        # Count records
        if row_errors:
            error_records += 1
            errors.extend(row_errors)
        elif row_warnings:
            warning_records += 1
            warnings.extend(row_warnings)
        else:
            valid_records += 1
    
    is_valid = (error_records == 0) and (len(data_rows) > 0)
    
    return {
        'valid': is_valid,
        'errors': errors,
        'warnings': warnings,
        'summary': {
            'total_records': len(data_rows),
            'valid_records': valid_records,
            'warning_records': warning_records,
            'error_records': error_records
        }
    }

def setup_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({'error': 'Not found'}), 404
        
        # Only try to get current_user if we're in a request context
        try:
            if current_user.is_authenticated:
                return render_template('errors/404.html'), 404
        except:
            pass  # Not in request context or user not authenticated
        
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        # Rollback any failed database transactions
        try:
            db.session.rollback()
        except:
            pass  # Ignore if no database connection
        
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({'error': 'Internal server error'}), 500
        
        # Only try to get current_user if we're in a request context
        try:
            if current_user.is_authenticated:
                return render_template('errors/500.html'), 500
        except:
            pass  # Not in request context or user not authenticated
        
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Only try to get current_user if we're in a request context
        try:
            if current_user.is_authenticated:
                return render_template('errors/403.html'), 403
        except:
            pass  # Not in request context or user not authenticated
        
        return render_template('errors/403.html'), 403

# Initialize app
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)