import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Clé secrète pour signer les sessions et les tokens (email vérification, mdp oublié)
    # EN PRODUCTION : définir SECRET_KEY comme variable d'environnement sur Render, jamais en dur ici.
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-me-in-production')

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'instance', 'vectis.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Configuration e-mail (Gmail SMTP) ---
    # Toutes ces valeurs viennent de variables d'environnement, jamais écrites en dur.
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')          # ex: vectis.contact@gmail.com
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')          # mot de passe d'application (16 caractères)
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME')

    # Durée de validité des liens envoyés par e-mail
    EMAIL_TOKEN_MAX_AGE = 3600          # 1h pour vérifier l'email
    RESET_TOKEN_MAX_AGE = 1800          # 30 min pour réinitialiser le mot de passe

    # Session utilisateur
    PERMANENT_SESSION_LIFETIME = timedelta(days=14)

    # --- Cloudflare Turnstile (anti-robot) ---
    # À obtenir gratuitement sur https://dash.cloudflare.com/ -> Turnstile
    TURNSTILE_SITE_KEY = os.environ.get('TURNSTILE_SITE_KEY', '')
    TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '')

    # Sécurité des cookies de session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # En production (HTTPS sur Render), on force le cookie sécurisé
    SESSION_COOKIE_SECURE = os.environ.get('RENDER', False) is not False
