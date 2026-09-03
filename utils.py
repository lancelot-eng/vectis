from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app, url_for
from flask_mail import Message
from app import mail

SALT_EMAIL_VERIFY = 'email-verify-salt'
SALT_PASSWORD_RESET = 'password-reset-salt'


def _serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])


def generate_token(email, salt):
    return _serializer().dumps(email, salt=salt)


def verify_token(token, salt, max_age):
    """Retourne l'email si le token est valide, sinon None."""
    try:
        return _serializer().loads(token, salt=salt, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


def send_verification_email(user_email):
    token = generate_token(user_email, SALT_EMAIL_VERIFY)
    link = url_for('auth.verify_email', token=token, _external=True)

    msg = Message(
        subject="Vérifiez votre adresse e-mail — Vectis",
        recipients=[user_email],
        body=(
            f"Bienvenue sur Vectis.\n\n"
            f"Confirmez votre adresse e-mail en cliquant sur ce lien "
            f"(valable 1 heure) :\n{link}\n\n"
            f"Si vous n'êtes pas à l'origine de cette inscription, ignorez ce message."
        ),
    )
    mail.send(msg)


def send_password_reset_email(user_email):
    token = generate_token(user_email, SALT_PASSWORD_RESET)
    link = url_for('auth.reset_password', token=token, _external=True)

    msg = Message(
        subject="Réinitialisation de votre mot de passe — Vectis",
        recipients=[user_email],
        body=(
            f"Une demande de réinitialisation de mot de passe a été faite "
            f"pour ce compte.\n\n"
            f"Cliquez sur ce lien pour choisir un nouveau mot de passe "
            f"(valable 30 minutes) :\n{link}\n\n"
            f"Si vous n'êtes pas à l'origine de cette demande, ignorez ce message : "
            f"votre mot de passe actuel reste inchangé."
        ),
    )
    mail.send(msg)


def verify_turnstile(token, remote_ip=None):
    """
    Vérifie un jeton Cloudflare Turnstile auprès de l'API Cloudflare.
    Retourne True si humain confirmé, False sinon.
    Si aucune clé secrète n'est configurée (dev local), on laisse passer
    pour ne pas bloquer le développement — mais ce n'est PAS sûr en production.
    """
    import requests

    secret = current_app.config.get('TURNSTILE_SECRET_KEY')
    if not secret:
        current_app.logger.warning("TURNSTILE_SECRET_KEY non configurée : vérification anti-robot ignorée.")
        return True

    if not token:
        return False

    try:
        resp = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={'secret': secret, 'response': token, 'remoteip': remote_ip},
            timeout=5,
        )
        result = resp.json()
        return result.get('success', False)
    except Exception as e:
        current_app.logger.error(f"Erreur vérification Turnstile: {e}")
        return False
