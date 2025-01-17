from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from models import Note, Shared_note, get_user_shares_note, get_note_shared_for_user
from utils.markdown_filter import markdown_to_safe_html
import utils.encrypter as encrypter
from utils.utils import handle_error
from utils.encrypter import check_password
from app import db
from models import User
from utils.validate import validate_password

note_routes = Blueprint('note_routes', __name__)

@note_routes.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    shared_notes = get_note_shared_for_user(current_user.id)

    notes_with_name = [
        {
            "note": note,
            "user_name": User.query.get(note.user_id).name
        }
        for note in shared_notes
    ]

    return render_template('dashboard.html', username=current_user.name, notes=notes, shared_notes=notes_with_name)

@note_routes.route('/add_note', methods=['POST'])
@login_required
def add_note():

    honeypot = request.form.get('extra_info', '')
    if honeypot:
        abort(400, "Nieautoryzowane żądanie.")

    note_content = request.form.get("note") 
    title = request.form.get("title")
    is_public = bool(request.form.get("is_public"))
    password = request.form.get("password", "")
    action = request.form.get("action")

    if not title:
        flash("Tytuł.", "error")
        return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
    if len(title) > 30:
        title = title[:30]  
    
    if not note_content:
        flash("Treść notatki jest wymagana.", "error")
        return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
    
    note = Note(
        note=note_content,
        user_id=current_user.id,
        is_public=is_public,
        title=title
    )

    if action == "Dodaj zaszyfrowaną notatkę":
        if not password:
            flash("Hasło jest wymagane do zaszyfrowania notatki.", "error")
            return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
        try:
            validate_password(password)
        except ValueError as e:
            flash(str(e), "note_password_error")
            return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
        note.note = markdown_to_safe_html(note.note)
        note.note = encrypter.encrypt_note(note.note, password)
        note.password = encrypter.hash_password(password)
        note.is_encrypted = True
        db.session.add(note)
        db.session.commit()
        return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))

    note.note = markdown_to_safe_html(note.note)
    db.session.add(note)
    db.session.commit()
    return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))


@note_routes.route('/note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_note(note_id):
    note = Note.query.get(note_id)

    if not note or note.user_id != current_user.id:
        return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
    
    shared_users = get_user_shares_note(note_id)

    if request.method == 'POST':
        password = request.form['password']
        try:
            correct_password = check_password(note.password, password)
            if correct_password:
                note.note = encrypter.decrypt_note(note.note, password)
                return render_template('note.html', note=note, has_been_decoded=True, shared_users=shared_users)
        except ValueError:
            flash("Niepoprawne hasło, spróbuj ponownie.", "verify_error")

    return render_template('note.html', note=note, has_been_decoded=False, shared_users=shared_users)

@note_routes.route('/view_public_note/<int:note_id>', methods=['GET', 'POST'])
def view_public_note(note_id):
    note = Note.query.get(note_id)

    if not note or not note.is_public:
        return redirect(url_for('note_routes.public_notes', _scheme='https', _external=True))
    
    is_encrypted = note.is_encrypted
    if request.method == 'POST':
        password = request.form['password']  
        try:
            correct_password = check_password(note.password, password)
            if correct_password:
                note.note = encrypter.decrypt_note(note.note, password)
                return render_template('public_note.html', note=note.note, has_been_decoded=True, is_encrypted=is_encrypted, title=note.title)
        except ValueError:
            flash("Niepoprawne hasło, spróbuj ponownie.", "verify_error")

    return render_template('public_note.html', note=note.note, has_been_decoded=False, is_encrypted=is_encrypted, title=note.title)

@note_routes.route('/shared_note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_shared_note(note_id):
    note = Note.query.get(note_id)
    if not note:
        return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
    
    shared_note = Shared_note.query.filter_by(note_id=note_id, user_id=current_user.id).first()

    if not shared_note:
        flash("Nie masz uprawnień do przeglądania tej notatki.", "error")
        return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
    
    is_encrypted = note.is_encrypted
    if request.method == 'POST':
        password = request.form['password']  
        try:
            correct_password = check_password(note.password, password)
            if correct_password:
                note.note = encrypter.decrypt_note(note.note, password)
                return render_template('shared_note.html', note=note.note, has_been_decoded=True, is_encrypted=is_encrypted, title=note.title)
        except ValueError:
            flash("Niepoprawne hasło, spróbuj ponownie.", "verify_error")

    return render_template('shared_note.html', note=note.note, has_been_decoded=False, is_encrypted=is_encrypted, title=note.title)


@note_routes.route('/public_notes', methods=['GET'])
def public_notes():
    notes = Note.query.filter_by(is_public=True).join(User).add_entity(User).all()
    return render_template('public_notes.html', notes=notes)

@note_routes.route('/update_visibility/<int:note_id>', methods=['POST'])
@login_required
def update_visibility(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    is_public = request.json.get('is_public', None)
    if is_public is None:
        return jsonify({'error': 'Invalid data'}), 400
    
    note.is_public = is_public
    db.session.commit()

    return jsonify({'success': True, 'is_public': note.is_public})


@note_routes.route('/add_shared_user/<int:note_id>', methods=['POST'])
@login_required
def add_shared_user(note_id):
    note = Note.query.get(note_id)

    if not note or note.user_id != current_user.id:
        return handle_error('Unauthorized', 403)

    name = request.json.get('username')
    if not name:
        return handle_error('No username provided')

    user = User.query.filter_by(name=name).first()
    if not user:
        return handle_error('User not found')

    if user.id == current_user.id:
        return handle_error('Cannot share with yourself')

    if user.id not in get_user_shares_note(note_id):
        shared_note = Shared_note(user_id=user.id, note_id=note_id)
        db.session.add(shared_note)
        db.session.commit()

        shared_users = [{'id': u.id, 'name': u.name} for u in get_user_shares_note(note_id)]
        return jsonify({'success': True, 'shared_with': shared_users, 'username': user.name, 'user_id': user.id})


@note_routes.route('/remove_shared_user/<int:note_id>', methods=['POST'])
@login_required
def remove_shared_user(note_id):
    note = Note.query.get(note_id)

    if not note or note.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'error': 'No user ID provided'}), 400

    shared_note = Shared_note.query.filter_by(note_id=note_id, user_id=user_id).first()
    if not shared_note:
        return jsonify({'error': 'User not found in shared list'}), 404

    db.session.delete(shared_note)
    db.session.commit()

    updated_shared_users = get_user_shares_note(note_id)
    updated_shared_users_data = [{'id': user.id, 'name': user.name} for user in updated_shared_users]

    return jsonify({'success': True, 'shared_with': updated_shared_users_data})
