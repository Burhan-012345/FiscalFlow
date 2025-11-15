import os
import secrets
import logging
from datetime import datetime, timedelta
import traceback
from flask import url_for, render_template, current_app
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from PIL import Image
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from werkzeug.utils import secure_filename

# Set up logging
logger = logging.getLogger(__name__)

class SecurityUtils:
    def __init__(self, app=None):
        self.app = app
        if app:
            self.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    def generate_token(self, data, salt=None):
        """Generate a secure token"""
        try:
            return self.serializer.dumps(data, salt=salt)
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            return None
    
    def verify_token(self, token, max_age=3600, salt=None):
        """Verify and decode a token"""
        try:
            data = self.serializer.loads(token, max_age=max_age, salt=salt)
            return data
        except Exception as e:
            logger.warning(f"Token verification failed: {e}")
            return None

class EmailUtils:
    def __init__(self, mail, app):
        self.mail = mail
        self.app = app
        self.logger = logging.getLogger(__name__)
    
    def send_otp_email(self, email, otp_code):
        """Send OTP verification email with comprehensive error handling"""
        try:
            subject = "FiscalFlow - Email Verification Code"
            
            # Fallback HTML content
            html_content = self._create_otp_email_fallback(otp_code)
            
            # Try to use template if it exists
            try:
                html_content = render_template('email/otp.html', 
                                             otp_code=otp_code,
                                             app_url=self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000'))
            except Exception as template_error:
                self.logger.warning(f"Email template not found, using fallback: {template_error}")
            
            success = self.send_email(email, subject, html_content)
            if success:
                self.logger.info(f"OTP email sent successfully to {email}")
            else:
                self.logger.error(f"Failed to send OTP email to {email}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error in send_otp_email: {str(e)}")
            return False
    
    def _create_otp_email_fallback(self, otp_code):
        """Create fallback OTP email content"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }}
                .content {{ padding: 30px; }}
                .otp-code {{ font-size: 42px; font-weight: bold; color: #667eea; text-align: center; margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; letter-spacing: 8px; }}
                .info-box {{ background: #e7f3ff; border-left: 4px solid #667eea; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }}
                .button {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    padding: 12px 30px; 
                    text-decoration: none; 
                    border-radius: 5px; 
                    display: inline-block; 
                    margin: 10px 0; 
                    font-weight: bold;
                    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 FiscalFlow</h1>
                    <p>Financial Management Simplified</p>
                </div>
                <div class="content">
                    <h2>Email Verification Required</h2>
                    <p>Hello,</p>
                    <p>Thank you for choosing FiscalFlow! To complete your registration and secure your account, please use the following verification code:</p>
                    
                    <div class="otp-code">{otp_code}</div>
                    
                    <div class="info-box">
                        <strong>Important:</strong>
                        <ul>
                            <li>This code will expire in 10 minutes</li>
                            <li>Do not share this code with anyone</li>
                            <li>If you didn't request this verification, please ignore this email</li>
                        </ul>
                    </div>
                    
                    <p>Enter this code in the verification page to activate your account and start managing your finances with FiscalFlow.</p>
                    
                    <p>Need help? Contact our support team at <a href="mailto:support@fiscalflow.com">support@fiscalflow.com</a></p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 FiscalFlow. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def send_password_reset(self, email, token):
        """Send password reset email with proper button styling - SUPPORTS LOCAL AND PRODUCTION"""
        try:
            # Determine base URL based on environment
            if self.app.config.get('DEBUG') or self.app.config.get('ENV') == 'development':
                # Local development URL
                base_url = "http://localhost:5000"
            else:
                # Production URL
                base_url = "https://fiscal01.pythonanywhere.com"
            
            reset_url = f"{base_url}/reset-password/{token}"
            
            self.logger.info(f"Generating password reset for: {email}")
            self.logger.info(f"Reset URL: {reset_url}")
            self.logger.info(f"Token: {token}")
            
            subject = "Reset Your FiscalFlow Password"
            
            # Try template first
            try:
                html_content = render_template('email/reset_password.html', 
                                             reset_url=reset_url,
                                             base_url=base_url)
                self.logger.info("Reset password template rendered successfully")
                
            except Exception as template_error:
                self.logger.warning(f"Reset password template not found, using fallback: {template_error}")
                html_content = self._create_password_reset_fallback(reset_url, base_url)
            
            # Log the HTML content for debugging
            self.logger.info(f"Email HTML content length: {len(html_content)}")
            
            success = self.send_email(email, subject, html_content)
            if success:
                self.logger.info(f"Password reset email sent successfully to {email}")
            else:
                self.logger.error(f"Failed to send password reset email to {email}")
            return success
            
        except Exception as e:
            self.logger.error(f"Error in send_password_reset: {str(e)}")
            self.logger.error(traceback.format_exc())
            return False
    
    def _create_password_reset_fallback(self, reset_url, base_url=None):
        """Create fallback password reset email content with proper button styling"""
        # Ensure we have the full URL
        if not reset_url.startswith(('http://', 'https://')):
            if not base_url:
                base_url = self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000')
            reset_url = f"{base_url}{reset_url}"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }}
                .content {{ padding: 30px; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }}
                .url-backup {{ 
                    word-break: break-all; 
                    background: #f8f9fa; 
                    padding: 12px; 
                    border-radius: 5px; 
                    margin: 10px 0; 
                    font-family: 'Courier New', monospace;
                    font-size: 14px;
                    border: 1px solid #e9ecef;
                }}
                .reset-button {{
                    background-color: #667eea;
                    border: 1px solid #667eea;
                    border-radius: 8px;
                    color: #ffffff;
                    display: inline-block;
                    font-family: Arial, sans-serif;
                    font-size: 16px;
                    font-weight: bold;
                    line-height: 1;
                    padding: 15px 35px;
                    text-decoration: none;
                    text-align: center;
                    margin: 20px 0;
                }}
                .reset-button:hover {{
                    background-color: #5a6fd8;
                    border-color: #5a6fd8;
                }}
                .info-box {{
                    background: #e7f3ff;
                    border-left: 4px solid #667eea;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 4px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 FiscalFlow</h1>
                    <p>Password Reset Request</p>
                </div>
                <div class="content">
                    <h2>Reset Your Password</h2>
                    <p>We received a request to reset your FiscalFlow account password.</p>
                    
                    <!-- Main Reset Button -->
                    <div style="text-align: center;">
                        <a href="{reset_url}" class="reset-button" target="_blank">
                            Reset Your Password
                        </a>
                    </div>
                    
                    <p>If the button doesn't work, copy and paste this link into your browser:</p>
                    <div class="url-backup">{reset_url}</div>
                    
                    <div class="info-box">
                        <strong>Security Notice:</strong>
                        <ul>
                            <li>This link will expire in 1 hour</li>
                            <li>If you didn't request this reset, please ignore this email</li>
                            <li>Your account security is important to us</li>
                        </ul>
                    </div>
                    
                    <p>For security reasons, this link can only be used once and will expire automatically.</p>
                    
                    <p>Need help? Contact our support team at <a href="mailto:support@fiscalflow.com">support@fiscalflow.com</a></p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 FiscalFlow. All rights reserved.</p>
                    <p>This is an automated security message.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def send_transaction_update(self, email, customer_name, transaction_type, amount, balance):
        """Send transaction update notification to customer"""
        try:
            subject = f"Transaction Update - {customer_name}"
            
            # Fallback HTML content
            html_content = self._create_transaction_update_fallback(customer_name, transaction_type, amount, balance)
            
            # Try template
            try:
                html_content = render_template('email/transaction_update.html',
                                            customer_name=customer_name,
                                            transaction_type=transaction_type,
                                            amount=amount,
                                            balance=balance,
                                            app_url=self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000'))
            except Exception as template_error:
                self.logger.warning(f"Transaction update template not found: {template_error}")
            
            success = self.send_email(email, subject, html_content)
            if success:
                self.logger.info(f"Transaction update sent to {email}")
            return success
            
        except Exception as e:
            self.logger.error(f"Error in send_transaction_update: {str(e)}")
            return False
    
    def _create_transaction_update_fallback(self, customer_name, transaction_type, amount, balance):
        """Create fallback transaction update email content"""
        transaction_type_display = transaction_type.replace('_', ' ').title()
        amount_formatted = f"${amount:,.2f}"
        balance_formatted = f"${balance:,.2f}"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
                .header {{ background: linear-gradient(135deg, #20bf6b 0%, #01baef 100%); color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 25px; }}
                .transaction-details {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .amount {{ font-size: 24px; font-weight: bold; color: #20bf6b; text-align: center; margin: 15px 0; }}
                .balance {{ font-size: 20px; color: #2d3436; text-align: center; margin: 15px 0; }}
                .footer {{ background: #f8f9fa; padding: 15px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }}
                .view-details-button {{
                    background: linear-gradient(135deg, #20bf6b 0%, #01baef 100%);
                    color: white;
                    padding: 12px 25px;
                    text-decoration: none;
                    border-radius: 6px;
                    display: inline-block;
                    margin: 15px 0;
                    font-weight: bold;
                    box-shadow: 0 4px 15px rgba(32, 191, 107, 0.3);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>💳 FiscalFlow</h1>
                    <p>Transaction Notification</p>
                </div>
                <div class="content">
                    <h2>Hello {customer_name},</h2>
                    <p>A new transaction has been recorded in your account:</p>
                    
                    <div class="transaction-details">
                        <div class="amount">{transaction_type_display}: {amount_formatted}</div>
                        <div class="balance">Current Balance: {balance_formatted}</div>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="{self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000')}/dashboard" class="view-details-button">View Account Details</a>
                    </div>
                    
                    <p>This is an automated notification from FiscalFlow.</p>
                    <p>If you have any questions about this transaction, please contact your account manager.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 FiscalFlow. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def send_balance_update(self, email, customer_name, balance):
        """Send balance update notification to customer"""
        try:
            subject = f"Account Balance Update - {customer_name}"
            
            # Fallback HTML content
            html_content = self._create_balance_update_fallback(customer_name, balance)
            
            # Try template
            try:
                html_content = render_template('email/balance_update.html',
                                            customer_name=customer_name,
                                            balance=balance,
                                            app_url=self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000'))
            except Exception as template_error:
                self.logger.warning(f"Balance update template not found: {template_error}")
            
            success = self.send_email(email, subject, html_content)
            if success:
                self.logger.info(f"Balance update sent to {email}")
            return success
            
        except Exception as e:
            self.logger.error(f"Error in send_balance_update: {str(e)}")
            return False
    
    def _create_balance_update_fallback(self, customer_name, balance):
        """Create fallback balance update email content"""
        balance_formatted = f"${balance:,.2f}"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
                .header {{ background: linear-gradient(135deg, #a55eea 0%, #8854d0 100%); color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 25px; }}
                .balance-display {{ background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; }}
                .balance-amount {{ font-size: 32px; font-weight: bold; color: #a55eea; margin: 10px 0; }}
                .footer {{ background: #f8f9fa; padding: 15px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }}
                .view-account-button {{
                    background: linear-gradient(135deg, #a55eea 0%, #8854d0 100%);
                    color: white;
                    padding: 12px 25px;
                    text-decoration: none;
                    border-radius: 6px;
                    display: inline-block;
                    margin: 15px 0;
                    font-weight: bold;
                    box-shadow: 0 4px 15px rgba(165, 94, 234, 0.3);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>💰 FiscalFlow</h1>
                    <p>Balance Update</p>
                </div>
                <div class="content">
                    <h2>Hello {customer_name},</h2>
                    <p>Your account balance has been updated:</p>
                    
                    <div class="balance-display">
                        <div style="font-size: 16px; color: #666;">Current Balance</div>
                        <div class="balance-amount">{balance_formatted}</div>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="{self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000')}/dashboard" class="view-account-button">View Account</a>
                    </div>
                    
                    <p>This is an automated notification from FiscalFlow.</p>
                    <p>For detailed transaction history, please log in to your account or contact your account manager.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 FiscalFlow. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def send_welcome_email(self, email, customer_name):
        """Send welcome email to new customers"""
        try:
            subject = "Welcome to FiscalFlow!"
            
            html_content = self._create_welcome_email_fallback(customer_name)
            
            # Try template
            try:
                html_content = render_template('email/welcome.html',
                                            customer_name=customer_name,
                                            app_url=self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000'))
            except Exception as template_error:
                self.logger.warning(f"Welcome email template not found: {template_error}")
            
            success = self.send_email(email, subject, html_content)
            if success:
                self.logger.info(f"Welcome email sent to {email}")
            return success
            
        except Exception as e:
            self.logger.error(f"Error in send_welcome_email: {str(e)}")
            return False
    
    def _create_welcome_email_fallback(self, customer_name):
        """Create fallback welcome email content"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }}
                .content {{ padding: 30px; }}
                .feature {{ display: flex; align-items: center; margin: 15px 0; }}
                .feature-icon {{ font-size: 24px; margin-right: 15px; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }}
                .get-started-button {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 15px 35px;
                    text-decoration: none;
                    border-radius: 8px;
                    display: inline-block;
                    margin: 20px 0;
                    font-size: 16px;
                    font-weight: bold;
                    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Welcome to FiscalFlow!</h1>
                    <p>Financial Management Simplified</p>
                </div>
                <div class="content">
                    <h2>Hello {customer_name},</h2>
                    <p>Welcome to FiscalFlow! We're excited to help you manage your finances effectively.</p>
                    
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin-top: 0;">What you can do with FiscalFlow:</h3>
                        <div class="feature">
                            <div class="feature-icon">💳</div>
                            <div>Track income and expenses</div>
                        </div>
                        <div class="feature">
                            <div class="feature-icon">📊</div>
                            <div>View detailed financial reports</div>
                        </div>
                        <div class="feature">
                            <div class="feature-icon">🔔</div>
                            <div>Receive transaction notifications</div>
                        </div>
                        <div class="feature">
                            <div class="feature-icon">📱</div>
                            <div>Access your account anywhere</div>
                        </div>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="{self.app.config.get('FISCALFLOW_URL', 'http://localhost:5000')}/dashboard" class="get-started-button">Get Started</a>
                    </div>
                    
                    <p>Need help getting started? Our support team is here to assist you.</p>
                    <p>Best regards,<br>The FiscalFlow Team</p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 FiscalFlow. All rights reserved.</p>
                    <p>This is an automated welcome message.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def send_email(self, to, subject, html_body):
        """Send email with comprehensive error handling and connection testing"""
        try:
            # Validate email configuration
            required_config = ['MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD']
            for config_key in required_config:
                if not self.app.config.get(config_key):
                    self.logger.error(f"Missing email configuration: {config_key}")
                    return False
            
            # Test connection before sending
            if not self._test_email_connection():
                self.logger.error("Email connection test failed")
                return False
            
            # Create message
            msg = Message(
                subject=subject,
                recipients=[to],
                html=html_body,
                sender=self.app.config['MAIL_DEFAULT_SENDER'],
                reply_to=self.app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            # Send email
            self.mail.send(msg)
            self.logger.info(f"Email sent successfully to {to}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            self.logger.error(f"SMTP Authentication failed: {e}")
            self.logger.error("Please check:")
            self.logger.error("1. Email username and password are correct")
            self.logger.error("2. For Gmail: Enable 2FA and use App Password")
            self.logger.error("3. For other providers: Check SMTP settings")
            return False
            
        except smtplib.SMTPConnectError as e:
            self.logger.error(f"SMTP Connection failed: {e}")
            self.logger.error("Please check:")
            self.logger.error("1. MAIL_SERVER and MAIL_PORT are correct")
            self.logger.error("2. Internet connection is available")
            self.logger.error("3. Firewall allows SMTP connections")
            return False
            
        except smtplib.SMTPSenderRefused as e:
            self.logger.error(f"SMTP Sender refused: {e}")
            return False
            
        except smtplib.SMTPRecipientsRefused as e:
            self.logger.error(f"SMTP Recipient refused: {e}")
            return False
            
        except smtplib.SMTPException as e:
            self.logger.error(f"SMTP error occurred: {e}")
            return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error sending email: {e}")
            return False
    
    def _test_email_connection(self):
        """Test SMTP connection without sending email"""
        try:
            server = smtplib.SMTP(self.app.config['MAIL_SERVER'], self.app.config['MAIL_PORT'])
            server.ehlo()
            
            if self.app.config.get('MAIL_USE_TLS'):
                server.starttls()
                server.ehlo()
            
            server.login(self.app.config['MAIL_USERNAME'], self.app.config['MAIL_PASSWORD'])
            server.quit()
            
            self.logger.info("Email connection test successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Email connection test failed: {e}")
            return False

class FileUtils:
    @staticmethod
    def allowed_file(filename, allowed_extensions=None):
        """Check if file extension is allowed"""
        if allowed_extensions is None:
            allowed_extensions = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}
        
        if '.' not in filename:
            return False
        
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in allowed_extensions
    
    @staticmethod
    def save_uploaded_file(file, upload_folder, max_size=(800, 600)):
        """Save uploaded file with validation and processing"""
        try:
            if not file or not FileUtils.allowed_file(file.filename):
                return None
            
            # Generate secure filename
            original_name = secure_filename(file.filename)
            file_extension = original_name.rsplit('.', 1)[1].lower() if '.' in original_name else ''
            random_prefix = secrets.token_hex(8)
            filename = f"{random_prefix}_{original_name}"
            filepath = os.path.join(upload_folder, filename)
            
            # Create upload folder if it doesn't exist
            os.makedirs(upload_folder, exist_ok=True)
            
            # Save file
            file.save(filepath)
            
            # Process image files (resize)
            if file_extension in ['png', 'jpg', 'jpeg']:
                try:
                    with Image.open(filepath) as img:
                        # Convert to RGB if necessary
                        if img.mode in ('RGBA', 'P'):
                            img = img.convert('RGB')
                        
                        # Resize if larger than max_size
                        if img.size[0] > max_size[0] or img.size[1] > max_size[1]:
                            img.thumbnail(max_size, Image.Resampling.LANCZOS)
                            img.save(filepath, optimize=True, quality=85)
                except Exception as img_error:
                    logger.warning(f"Image processing failed, keeping original: {img_error}")
            
            logger.info(f"File saved successfully: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            return None
    
    @staticmethod
    def delete_file(filename, upload_folder):
        """Delete uploaded file"""
        try:
            if filename:
                filepath = os.path.join(upload_folder, filename)
                if os.path.exists(filepath):
                    os.remove(filepath)
                    logger.info(f"File deleted: {filename}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return False

class OTPUtils:
    @staticmethod
    def generate_otp(length=6):
        """Generate a secure OTP code"""
        return ''.join(secrets.choice('0123456789') for _ in range(length))
    
    @staticmethod
    def is_otp_valid(otp_record):
        """Check if OTP is valid and not expired"""
        if not otp_record:
            return False
        if otp_record.is_used:
            return False
        if otp_record.expires_at <= datetime.utcnow():
            return False
        return True
    
    @staticmethod
    def cleanup_expired_otps(db_session, OTPModel):
        """Clean up expired OTP records"""
        try:
            expired_count = OTPModel.query.filter(
                OTPModel.expires_at <= datetime.utcnow()
            ).delete()
            db_session.commit()
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired OTP records")
            return expired_count
        except Exception as e:
            logger.error(f"Error cleaning up expired OTPs: {e}")
            db_session.rollback()
            return 0

class ReportUtils:
    @staticmethod
    def generate_pdf_report(customer, transactions):
        """Generate PDF report for customer transactions using HTML template (PythonAnywhere compatible)"""
        try:
            logger.info(f"Starting PDF generation for customer: {customer.name}")

            from weasyprint import HTML
            from weasyprint.text.fonts import FontConfiguration
            logger.info("WeasyPrint imported successfully")

            # Generate HTML using Jinja2
            logger.info("Rendering pdf_template.html...")
            html_content = render_template(
                'pdf_template.html',
                customer=customer,
                transactions=transactions,
                generated_at=datetime.utcnow()
            )

            if not html_content or not html_content.strip():
                raise Exception("Rendered HTML content is empty")

            logger.info(f"HTML content length: {len(html_content)} characters")

            font_config = FontConfiguration()

            # IMPORTANT FIX FOR PYTHONANYWHERE →
            # Must set base_url to allow assets & prevent PDF.__init__() error
            html_obj = HTML(
                string=html_content,
                base_url=current_app.root_path
            )

            logger.info("Converting HTML to PDF...")
            pdf = html_obj.write_pdf(font_config=font_config)

            if not pdf:
                raise Exception("PDF generation returned empty content")

            logger.info(f"PDF generated successfully ({len(pdf)} bytes)")
            return pdf

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            logger.error(traceback.format_exc())
            raise Exception(f"PDF generation failed: {e}")

    @staticmethod
    def generate_excel_report(customer, transactions):
        """Generate Excel report for customer transactions"""
        try:
            logger.info(f"Starting Excel generation for customer: {customer.name}")
            
            # Try using openpyxl
            try:
                from openpyxl import Workbook
                from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
                from openpyxl.utils import get_column_letter
                from io import BytesIO
                
                logger.info("Openpyxl imported successfully")
                
                # Create workbook and worksheet
                wb = Workbook()
                ws = wb.active
                ws.title = f"{customer.name} Transactions"
                
                # Define styles
                header_font = Font(bold=True, color="FFFFFF")
                header_fill = PatternFill(start_color="1565C0", end_color="1565C0", fill_type="solid")
                center_align = Alignment(horizontal='center', vertical='center')
                thin_border = Border(left=Side(style='thin'), 
                                   right=Side(style='thin'),
                                   top=Side(style='thin'), 
                                   bottom=Side(style='thin'))
                
                # Customer Information
                ws.merge_cells('A1:E1')
                ws['A1'] = f"Transaction Report - {customer.name}"
                ws['A1'].font = Font(bold=True, size=16, color="1565C0")
                ws['A1'].alignment = center_align
                
                ws['A3'] = "Customer Information"
                ws['A3'].font = Font(bold=True)
                
                customer_info = [
                    ["Customer:", customer.name],
                    ["Email:", customer.email or 'N/A'],
                    ["Phone:", customer.phone or 'N/A'],
                    ["Current Balance:", f"₹{customer.current_balance:,.2f}"],
                    ["Credit Limit:", f"₹{customer.credit_limit:,.2f}" if customer.credit_limit > 0 else 'No Limit']
                ]
                
                for i, (label, value) in enumerate(customer_info, start=4):
                    ws[f'A{i}'] = label
                    ws[f'A{i}'].font = Font(bold=True)
                    ws[f'B{i}'] = value
                
                # Transactions Header
                headers = ['Date', 'Type', 'Amount (₹)', 'Category', 'Notes']
                for col, header in enumerate(headers, start=1):
                    cell = ws.cell(row=9, column=col, value=header)
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = center_align
                    cell.border = thin_border
                
                # Transactions Data
                row_num = 10
                for transaction in transactions:
                    ws.cell(row=row_num, column=1, value=transaction.date.strftime('%Y-%m-%d')).border = thin_border
                    ws.cell(row=row_num, column=2, value=transaction.type.replace('_', ' ').title()).border = thin_border
                    
                    amount_cell = ws.cell(row=row_num, column=3, value=transaction.amount)
                    amount_cell.number_format = '#,##0.00'
                    amount_cell.border = thin_border
                    
                    ws.cell(row=row_num, column=4, value=transaction.category or 'General').border = thin_border
                    ws.cell(row=row_num, column=5, value=transaction.notes or '').border = thin_border
                    row_num += 1
                
                # Summary
                summary_row = row_num + 2
                cash_in_total = sum(t.amount for t in transactions if t.type == 'cash_in')
                cash_out_total = sum(t.amount for t in transactions if t.type == 'cash_out')
                
                summary_data = [
                    ["Total Transactions:", len(transactions)],
                    ["Total Cash In:", f"₹{cash_in_total:,.2f}"],
                    ["Total Cash Out:", f"₹{cash_out_total:,.2f}"],
                    ["Generated on:", datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')]
                ]
                
                for i, (label, value) in enumerate(summary_data, start=summary_row):
                    ws[f'A{i}'] = label
                    ws[f'A{i}'].font = Font(bold=True)
                    ws[f'B{i}'] = value
                
                # Auto-adjust column widths
                for column in ws.columns:
                    max_length = 0
                    column_letter = get_column_letter(column[0].column)
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = (max_length + 2)
                    ws.column_dimensions[column_letter].width = adjusted_width
                
                # Save to BytesIO
                excel_buffer = BytesIO()
                wb.save(excel_buffer)
                excel_content = excel_buffer.getvalue()
                excel_buffer.close()
                
                logger.info(f"Excel report generated successfully for customer: {customer.name}")
                return excel_content
                
            except ImportError:
                logger.error("Openpyxl not installed. Install with: pip install openpyxl")
                raise Exception("Openpyxl is required for Excel generation. Please install it with: pip install openpyxl")
                
            except Exception as e:
                logger.error(f"Excel generation failed: {e}")
                raise Exception(f"Excel generation error: {str(e)}")
                
        except Exception as e:
            logger.error(f"Excel generation completely failed: {e}")
            raise Exception(f"Failed to generate Excel: {str(e)}")