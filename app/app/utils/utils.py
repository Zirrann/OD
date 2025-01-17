from models import User
from flask import jsonify
import os

def is_login_or_email_taken(login, email):
    return User.query.filter_by(login=login).first() or User.query.filter_by(email=email).first()

def handle_error(message, status_code=400):
    return jsonify({'error': message}), status_code