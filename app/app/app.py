from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

db = SQLAlchemy() 
migrate = Migrate()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address) 
csrf = CSRFProtect()

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

from flask import Flask

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "https://*.qrserver.com"],
        'font-src': ["'self'"],
        'object-src': ["'none'"],
        'connect-src': ["'self'"] 
    }

    Talisman(app, content_security_policy=csp)


    from routes.auth_routes import auth_routes
    from routes.note_routes import note_routes
    app.register_blueprint(auth_routes, url_prefix='/')
    app.register_blueprint(note_routes, url_prefix='/')

    return app
