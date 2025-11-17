from flask_wtf import FlaskForm
from wtforms import DateTimeField, StringField, PasswordField, EmailField, SelectField, TextAreaField, FloatField, DateField, BooleanField, FileField, TimeField  
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional
import re

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')

class RegistrationStep1Form(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])

class OTPVerificationForm(FlaskForm):
    otp = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])

class PasswordSetupForm(FlaskForm):
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

class AccountForm(FlaskForm):
    name = StringField('Account Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    currency = SelectField('Currency', choices=[
        ('INR', 'Indian Rupee (₹)')  # Only INR option
    ], default='INR')

class CustomerForm(FlaskForm):
    name = StringField('Customer Name', validators=[DataRequired(), Length(max=100)])
    email = EmailField('Email', validators=[Optional(), Email()])
    phone = StringField('Phone')
    category = StringField('Category')

class TransactionForm(FlaskForm):
    type = SelectField('Type', choices=[
        ('cash_in', 'Cash In'),
        ('cash_out', 'Cash Out')
    ], validators=[Optional()])  
    amount = FloatField('Amount', validators=[DataRequired()])
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])  
    time = TimeField('Time', format='%H:%M', validators=[DataRequired()])     
    category = StringField('Category', validators=[DataRequired()])  
    notes = TextAreaField('Notes', validators=[Optional()])
    attachment = FileField('Attachment', validators=[Optional()])

class BulkImportForm(FlaskForm):
    file = FileField('Excel File', validators=[DataRequired()])

def validate_password_strength(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number')