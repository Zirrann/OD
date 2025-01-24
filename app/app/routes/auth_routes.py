from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_login import login_user, login_required, logout_user, current_user 
from werkzeug.security import generate_password_hash
from app import db, limiter
from models import User, VerificationCode, UserLogin
import utils.encrypter as encrypter
import random
import string
from datetime import datetime, timedelta
import pyotp
import utils.validate as validate


auth_routes = Blueprint('auth_routes', __name__)

def login_user_with_ip(user):
    ip_address = request.remote_addr
    user_login = UserLogin(user_id=user.id, ip_address=ip_address)
    db.session.add(user_login)
    db.session.commit()

    login_user(user)

@auth_routes.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute", error_message="Za dużo zapytań. Spróbuj ponownie za chwilę")
def index():
    if request.method == 'POST':
        honeypot = request.form.get('user_email')
        if honeypot:
            abort(400, "Nieautoryzowane żądanie.")

        login = request.form.get('login')
        password = request.form.get('password')

        if 'login_valid' in session and session['login_valid']:
            login = session.get('login')
            password = session.get('password')

        try:
            user = encrypter.check_login_credentials(login, password)

            if not user:
                session['login_valid'] = False
                session.pop('login', None)
                session.pop('password', None)
                limiter.limit("5 per minute", error_message="Za dużo błędnych prób logowania. Spróbuj ponownie za chwilę.")(index)
                flash("Niepoprawny login lub hasło", "login_error")
                return render_template('index.html',show_login_form=True)

            session['login_valid'] = True
            session['login'] = login
            session['password'] = password

            if not user.two_factor_enabled:
                login_user_with_ip(user)
                session.pop('login_valid', None)
                return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))

            otp = request.form.get('otp')
            if not otp:
                flash("Proszę wprowadzić kod TOTP.", "otp_error")
                return render_template('index.html', user=user, show_login_form=False)

            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(otp):
                flash("Nieprawidłowy kod TOTP", "otp_error")
                return render_template('index.html', user=user, show_login_form=False)

            login_user_with_ip(user)
            session.pop('login_valid', None)
            return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))

        except ValueError as e:
            limiter.limit("5 per minute", error_message="Za dużo błędnych prób logowania. Spróbuj ponownie za chwilę.")(index)
            flash("Niepoprawny login lub hasło", "login_error")

    show_login_form = not session.get('login_valid', False)
    return render_template('index.html', show_login_form=show_login_form)


@auth_routes.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute", error_message="Za dużo zapytań. Spróbuj ponownie za chwilę")
def register():
    if request.method == 'POST':
        name = request.form['name']
        login = request.form['login']
        password = request.form['password']
        email = request.form['email']
        registration_code = request.form['registration_code']

        verificationCode = VerificationCode.query.filter_by(email=email).first()

        if not verificationCode:
            flash('Aby się zarejestrować wyślil najpierw kod na email')
            return render_template('register.html')
        
        if verificationCode.code != registration_code:
            flash('Niepoprawny kod, 1')           
            return render_template('register.html')
        
        if verificationCode.is_expired():
            flash('Niepoprawny kod')  
            return render_template('register.html', error="Kod weryfikacyjny wygasł.")
        
        try:
            encrypter.register_user(name=name, login=login, password=password, email=email)
        except ValueError as e:
            flash(str(e), "validation_error")   
            return render_template('register.html')

        flash('Rejestracja zakończona sukcesem! Zaloguj się.', 'success')
        return redirect(url_for('auth_routes.index', _scheme='https', _external=True))
    
    return render_template('register.html')


@auth_routes.route('/send_registration_code', methods=['POST'])
@limiter.limit("3 per minute", error_message="Za dużo prób. Spróbuj ponownie za chwilę.")
def send_registration_code():
    email = request.form['email']
    
    try:
        validate.validate_email(email)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"message": "Użytkownik o tym adresie e-mail już istnieje."}), 400
    
    code = generate_code()
    expires_at = datetime.utcnow() + timedelta(hours=1) 

    verification_code = VerificationCode.query.filter_by(email=email).first()

    if verification_code:
        verification_code.code = code
        verification_code.expires_at = expires_at
        db
    else:
        verification_code = VerificationCode(email=email, code=code, expires_at=expires_at)
        db.session.add(verification_code)
    db.session.commit()

    return jsonify({"message": f'Kod rejestracyjny zostałby wysłany na adres {email} z kodem: {code}'}), 200

@auth_routes.route('/enable_2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute", error_message="Za dużo zapytań. Spróbuj ponownie za chwilę")
@login_required
def enable_2fa():
    user = User.query.filter_by(id=current_user.id).one()
    
    if not user.two_factor_enabled and not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="Notes App")
    
    if user.two_factor_enabled:
        if request.method == 'POST':
            user.two_factor_enabled = False
            db.session.commit()
            flash("2FA zostało wyłączone.", "success")
            return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
        return render_template('enable_2fa.html', provisioning_uri=provisioning_uri, two_factor_enabled=True)

    if request.method == 'POST':
        otp = request.form.get('otp')  

        if otp and totp.verify(otp): 
            user.two_factor_enabled = True
            db.session.commit()
            flash("2FA zostało pomyślnie włączone!", "success")
            return redirect(url_for('note_routes.dashboard', _scheme='https', _external=True))
        else:
            flash("Nieprawidłowy kod OTP. Spróbuj ponownie.", "error")

    return render_template('enable_2fa.html', provisioning_uri=provisioning_uri, two_factor_enabled=False)

@auth_routes.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("10 per minute", error_message="Za dużo zapytań. Spróbuj ponownie za chwilę")
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        reset_code = request.form['reset_code']
        new_password = request.form['new_password']

        try:
            validate.validate_password(new_password)
        except ValueError as e:
            flash(str(e), "error")
            return render_template('reset_password.html')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Nie znaleziono użytkownika o podanym adresie e-mail.", "error")
            return render_template('reset_password.html')

        if user.reset_code != reset_code:
            flash("Nieprawidłowy kod resetu hasła.", "error")
            return render_template('reset_password.html')

        if user.reset_code_expiry and datetime.utcnow() > user.reset_code_expiry:
            flash("Kod weryfikacyjny wygasł.", "error")
            return render_template('reset_password.html')

        user.password = encrypter.hash_password(new_password)
        user.reset_code = None
        user.reset_code_expiry = None 

        db.session.commit()
        limiter.limit("1 per hour", error_message="Za dużo prób resetu hasła. Spróbuj ponownie za godzinę.")(reset_password)
        flash("Hasło zostało zmienione pomyślnie! Możesz się teraz zalogować.", "success")
        redirect(url_for('auth_routes.index', _scheme='https', _external=True))

    return render_template('reset_password.html')


@auth_routes.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth_routes.index', _scheme='https', _external=True))

def generate_code(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@auth_routes.route('/send_reset_code', methods=['POST'])
@limiter.limit("3 per minute", error_message="Za dużo prób. Spróbuj ponownie za chwilę.")
def send_reset_code():
    email = request.form['email'] 
        
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Nie możem wysłać kodu na podany email."}), 400
    
    code = generate_code()
    expires_at = datetime.utcnow() + timedelta(hours=1) 

    user.reset_code = code
    user.reset_code_expiry = expires_at
    db.session.commit()

    return jsonify({"message": f'Kod rejestracyjny zostałby wysłany na adres {email} z kodem: {code}'}), 200


@auth_routes.route('/password', methods=['POST'])
def password():
    data = request.get_json()
    password = data.get("password")

    if not password:
        return jsonify({"error": "Hasło nie zostało przekazane"}), 400
    
    entropy = validate.calculate_entropy(password)  

    if entropy < 30:
        strength = "weak"
    elif entropy < 50:
        strength = "medium"
    else:
        strength = "strong"
    
    return jsonify({
        "entropy": entropy,
        "strength": strength
    })

@limiter.limit("10 per minute", error_message="Za dużo prób. Spróbuj ponownie za chwilę.")
@auth_routes.route('/login_history_page', methods=['GET'])
@login_required
def login_history_page():
    login_history = UserLogin.query.filter_by(user_id=current_user.id).all()

    return render_template('login_history.html', login_history=login_history)

@auth_routes.route('/clear', methods=['GET'])
def clear():
    session_keys_to_remove = ['login_valid', 'login', 'password']
    
    for key in session_keys_to_remove:
        session.pop(key, None)

    return redirect(url_for('auth_routes.index', _scheme='https', _external=True))