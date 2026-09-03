import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    os.makedirs(os.path.join(app.root_path, '..', 'instance'), exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    from app.security import limiter
    limiter.init_app(app)

    login_manager.login_view = 'auth.index'

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.tickets import tickets_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(admin_bp)

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
            "frame-src https://challenges.cloudflare.com; "
            "connect-src 'self' https://challenges.cloudflare.com;"
        )
        return response

    with app.app_context():
        db.create_all()

    return app
