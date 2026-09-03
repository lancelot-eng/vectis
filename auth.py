import re
from flask import Blueprint, request, jsonify, redirect, url_for, render_template, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, ROLE_ADMIN, ROLE_USER
from app.utils import (
    send_verification_email, send_password_reset_email,
    verify_token, verify_turnstile, SALT_EMAIL_VERIFY, SALT_PASSWORD_RESET
)
from app.security import limiter
from app.disposable_domains import DISPOSABLE_DOMAINS

auth_bp = Blueprint('auth', __name__)

EMAIL_REGEX = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


@auth_bp.route('/')
def index():
    # Point d'entrée simple si on veut rediriger vers l'accueil
    return redirect(url_for('main.index'))


@auth_bp.route('/api/register', methods=['POST'])
@limiter.limit('5 per hour')
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    consent = data.get('consent', False)
    turnstile_token = data.get('turnstile_token', '')

    if not verify_turnstile(turnstile_token, request.remote_addr):
        return jsonify({'error': "Vérification anti-robot échouée. Réessayez."}), 400

    # --- Validations serveur (jamais confiance au frontend seul) ---
    if not consent:
        return jsonify({'error': "Vous devez accepter la politique de confidentialité."}), 400

    if not (3 <= len(username) <= 32) or not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        return jsonify({'error': "Nom d'utilisateur invalide (3-32 caractères, sans espaces ni caractères spéciaux)."}), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({'error': "Adresse e-mail invalide."}), 400

    email_domain = email.rsplit('@', 1)[-1].lower()
    if email_domain in DISPOSABLE_DOMAINS:
        return jsonify({'error': "Les adresses e-mail jetables/temporaires ne sont pas acceptées. Utilisez une adresse e-mail personnelle valide."}), 400

    if len(password) < 8:
        return jsonify({'error': "Le mot de passe doit contenir au moins 8 caractères."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': "Ce nom d'utilisateur est déjà utilisé."}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({'error': "Cette adresse e-mail est déjà associée à un compte."}), 409

    # Le tout premier compte créé sur la plateforme devient automatiquement admin
    is_first_user = User.query.count() == 0

    user = User(
        username=username,
        email=email,
        role=ROLE_ADMIN if is_first_user else ROLE_USER,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    try:
        send_verification_email(user.email)
    except Exception as e:
        # On ne bloque pas l'inscription si l'envoi échoue, mais on prévient.
        current_app_logger_fallback(e)
        return jsonify({
            'success': True,
            'warning': "Compte créé mais l'e-mail de vérification n'a pas pu être envoyé. Réessayez depuis la page de connexion."
        }), 201

    return jsonify({'success': True, 'message': "Compte créé. Vérifiez votre boîte e-mail pour l'activer."}), 201


def current_app_logger_fallback(e):
    # Petit garde-fou pour éviter un crash si le logger n'est pas configuré
    try:
        from flask import current_app
        current_app.logger.error(f"Erreur envoi email: {e}")
    except Exception:
        pass


@auth_bp.route('/verify-email/<token>')
def verify_email(token):
    email = verify_token(token, SALT_EMAIL_VERIFY, max_age=3600)
    if not email:
        return render_template('message.html',
                                title="Lien invalide ou expiré",
                                text="Ce lien de vérification n'est plus valide. Demandez-en un nouveau depuis la page de connexion.",
                                success=False)

    user = User.query.filter_by(email=email).first()
    if not user:
        return render_template('message.html', title="Compte introuvable",
                                text="Aucun compte associé à cet e-mail.", success=False)

    user.email_verified = True
    db.session.commit()
    return render_template('message.html',
                            title="E-mail vérifié",
                            text="Votre adresse e-mail est confirmée. Vous pouvez maintenant vous connecter.",
                            success=True)


@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get('identifier') or '').strip().lower()
    password = data.get('password') or ''
    turnstile_token = data.get('turnstile_token', '')

    if not verify_turnstile(turnstile_token, request.remote_addr):
        return jsonify({'error': "Vérification anti-robot échouée. Réessayez."}), 400

    user = User.query.filter(
        (User.email == identifier) | (User.username == identifier)
    ).first()

    # Message volontairement générique pour ne pas révéler si l'email existe (anti-énumération)
    generic_error = "Identifiants incorrects."

    if not user or not user.check_password(password):
        return jsonify({'error': generic_error}), 401

    if user.is_deleted:
        return jsonify({'error': generic_error}), 401

    if not user.email_verified:
        return jsonify({'error': "Adresse e-mail non vérifiée. Consultez votre boîte mail."}), 403

    login_user(user, remember=True)
    return jsonify({
        'success': True,
        'user': {'username': user.username, 'role': user.role}
    }), 200


@auth_bp.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True}), 200


@auth_bp.route('/api/forgot-password', methods=['POST'])
@limiter.limit('5 per hour')
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()

    user = User.query.filter_by(email=email).first()
    # Réponse identique que le compte existe ou non (anti-énumération d'emails)
    if user and not user.is_deleted:
        try:
            send_password_reset_email(user.email)
        except Exception as e:
            current_app_logger_fallback(e)

    return jsonify({
        'success': True,
        'message': "Si un compte existe avec cet e-mail, un lien de réinitialisation vient d'être envoyé."
    }), 200


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token, SALT_PASSWORD_RESET, max_age=1800)
    if not email:
        return render_template('message.html',
                                title="Lien invalide ou expiré",
                                text="Ce lien de réinitialisation n'est plus valide. Refaites une demande.",
                                success=False)

    if request.method == 'GET':
        return render_template('reset_password.html', token=token)

    new_password = request.form.get('password', '')
    if len(new_password) < 8:
        flash("Le mot de passe doit contenir au moins 8 caractères.")
        return render_template('reset_password.html', token=token)

    user = User.query.filter_by(email=email).first()
    if not user:
        return render_template('message.html', title="Compte introuvable",
                                text="Aucun compte associé à cet e-mail.", success=False)

    user.set_password(new_password)
    db.session.commit()
    return render_template('message.html',
                            title="Mot de passe mis à jour",
                            text="Vous pouvez maintenant vous connecter avec votre nouveau mot de passe.",
                            success=True)


@auth_bp.route('/api/me')
def me():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'username': current_user.username,
            'role': current_user.role,
        })
    return jsonify({'authenticated': False})
