from flask_login import UserMixin
from datetime import datetime, timedelta
from app import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    login = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    reset_code = db.Column(db.String(120), nullable=True)
    reset_code_expiry = db.Column(db.DateTime, nullable=True)

    two_factor_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(16))

    notes = db.relationship('Note', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.login}>'
    
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note = db.Column(db.String(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False, nullable=False)
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    password = db.Column(db.String(100), nullable=True)
    title = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return f'<Note {self.id}>'
    
class UserLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow) 

    def __repr__(self):
        return f'<UserLogin user_id={self.user_id}, ip={self.ip_address}, time={self.login_time}>' 
    
class Shared_note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)

    def __repr__(self):
        return f'<Shared Note {self.id}>'
    
class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    code = db.Column(db.String(50), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at
    

def get_note_shared_for_user(user_id):
    shared_notes = Note.query.join(Shared_note, Note.id == Shared_note.note_id).filter(
        Shared_note.user_id == user_id
    ).all()
    return shared_notes

def get_user_shares_note(note_id):
    shared_users = User.query.join(Shared_note, User.id == Shared_note.user_id).filter(
        Shared_note.note_id == note_id
    ).all()
    return shared_users