from datetime import datetime
from functools import wraps
from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from app import db
from app.models import User, ROLE_ADMIN, ROLE_MODERATOR, ROLE_USER

admin_bp = Blueprint('admin', __name__)


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': "Accès réservé à l'administrateur."}), 403
        return f(*args, **kwargs)
    return wrapper


@admin_bp.route('/admin')
@login_required
@admin_required
def admin_page():
    return render_template('admin.html')


@admin_bp.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    users = User.query.filter_by(deleted_at=None).order_by(User.created_at.desc()).all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'role': u.role,
        'email_verified': u.email_verified,
        'created_at': u.created_at.isoformat(),
    } for u in users])


@admin_bp.route('/api/admin/users/<int:user_id>/role', methods=['PATCH'])
@login_required
@admin_required
def set_role(user_id):
    target = User.query.get_or_404(user_id)

    if target.id == current_user.id:
        return jsonify({'error': "Vous ne pouvez pas modifier votre propre rôle."}), 400

    data = request.get_json(silent=True) or {}
    new_role = data.get('role')

    if new_role not in (ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN):
        return jsonify({'error': "Rôle invalide."}), 400

    target.role = new_role
    db.session.commit()
    return jsonify({'success': True, 'role': target.role})


@admin_bp.route('/api/account/delete', methods=['POST'])
@login_required
def delete_own_account():
    """
    Suppression de compte par l'utilisateur lui-même.
    Conforme à la politique affichée : soft-delete, données conservées
    6 mois, aucun email envoyé après cette action.
    """
    from flask_login import logout_user

    current_user.deleted_at = datetime.utcnow()
    db.session.commit()
    logout_user()
    return jsonify({'success': True})
