import os
from cryptography.fernet import Fernet
import hashlib
from models import User
from app import db
import utils.validate as validate
import base64

def get_key(password, salt=None):
    if not salt:
        salt = b'static_salt_value'
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_note(note_content, password):
    encryption_key = get_key(password)
    fernet = Fernet(encryption_key)
    encrypted_note = fernet.encrypt(note_content.encode())
    return encrypted_note.decode()

def decrypt_note(note_content, password):
    encryption_key = get_key(password)
    fernet = Fernet(encryption_key)
    encrypted_note = fernet.decrypt(note_content.encode())
    return encrypted_note.decode()

def hash_password(password):
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
    return f"pbkdf2:sha256${salt.hex()}${hashed_password.hex()}"

def check_password(hashed_password, password):
    validate.validate_password(password)

    _, salt, hashed = hashed_password.split('$')
    salt = bytes.fromhex(salt)
    hashed = bytes.fromhex(hashed)
    new_hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
    return new_hashed == hashed

def check_login_credentials(login, password):
    validate.validate_login(login, "Login")

    user = User.query.filter_by(login=login).first()
    if user and check_password(user.password, password):
        return user
    return None

def validate_register_user(login, name, password, email):
    validate.validate_login(login, "Login")
    validate.validate_login(name, "Nazwa użytkownika")
    validate.validate_password(password)
    validate.validate_email(email)


def register_user(name, login, password, email):
    validate.validate_login(login, "Login")
    validate.validate_login(name, "Nazwa użytkownika")
    validate.validate_password(password)
    validate.validate_email(email)

    if db.session.query(User).filter_by(name=name).first():
        raise ValueError("Nazwa użytkownika jest już zajęta.")
    
    if db.session.query(User).filter_by(email=email).first():
        raise ValueError("E-mail jest już zajęty.")
    
    hashed_password = hash_password(password)
    
    new_user = User(name=name, login=login, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()

    return new_user