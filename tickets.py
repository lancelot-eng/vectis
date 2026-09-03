import bleach
from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from app import db
from app.models import Ticket, TicketMessage, STATUS_OPEN, STATUS_RESOLVED

tickets_bp = Blueprint('tickets', __name__)

CATEGORIES = [
    "Problème de connexion",
    "Compte piraté / accès suspect",
    "Signaler un contenu",
    "Question technique",
    "Confidentialité / RGPD",
    "Suggestion",
    "Autre",
]

# Nettoyage strict : aucune balise HTML autorisée dans les messages (anti-XSS)
ALLOWED_TAGS = []


def sanitize(text):
    return bleach.clean(text or '', tags=ALLOWED_TAGS, strip=True)


@tickets_bp.route('/support')
@login_required
def support_page():
    return render_template('support.html', categories=CATEGORIES)


@tickets_bp.route('/api/tickets', methods=['GET'])
@login_required
def list_tickets():
    if current_user.is_moderator:
        # Modérateurs et admin voient tous les tickets de tout le monde
        tickets = Ticket.query.order_by(Ticket.updated_at.desc()).all()
    else:
        tickets = Ticket.query.filter_by(user_id=current_user.id) \
            .order_by(Ticket.updated_at.desc()).all()

    return jsonify([_serialize_ticket(t) for t in tickets])


@tickets_bp.route('/api/tickets', methods=['POST'])
@login_required
def create_ticket():
    data = request.get_json(silent=True) or {}
    subject = sanitize((data.get('subject') or '').strip())[:120]
    category = sanitize((data.get('category') or 'Autre').strip())[:60]
    first_message = sanitize((data.get('message') or '').strip())

    if not subject or not first_message:
        return jsonify({'error': "Le sujet et le message sont obligatoires."}), 400

    if category not in CATEGORIES:
        category = 'Autre'

    ticket = Ticket(subject=subject, category=category, user_id=current_user.id)
    db.session.add(ticket)
    db.session.flush()  # récupère ticket.id avant le commit

    msg = TicketMessage(ticket_id=ticket.id, user_id=current_user.id, body=first_message)
    db.session.add(msg)
    db.session.commit()

    return jsonify(_serialize_ticket(ticket, with_messages=True)), 201


@tickets_bp.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if not current_user.is_moderator and ticket.user_id != current_user.id:
        return jsonify({'error': "Accès refusé."}), 403

    return jsonify(_serialize_ticket(ticket, with_messages=True))


@tickets_bp.route('/api/tickets/<int:ticket_id>/messages', methods=['POST'])
@login_required
def add_message(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if not current_user.is_moderator and ticket.user_id != current_user.id:
        return jsonify({'error': "Accès refusé."}), 403

    data = request.get_json(silent=True) or {}
    body = sanitize((data.get('body') or '').strip())

    if not body:
        return jsonify({'error': "Le message ne peut pas être vide."}), 400

    msg = TicketMessage(ticket_id=ticket.id, user_id=current_user.id, body=body)
    db.session.add(msg)
    ticket.status = STATUS_OPEN  # une réponse rouvre le ticket s'il était résolu
    db.session.commit()

    return jsonify(_serialize_message(msg)), 201


@tickets_bp.route('/api/tickets/<int:ticket_id>/status', methods=['PATCH'])
@login_required
def update_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Seuls modérateurs/admin ou l'auteur peuvent marquer résolu
    if not current_user.is_moderator and ticket.user_id != current_user.id:
        return jsonify({'error': "Accès refusé."}), 403

    data = request.get_json(silent=True) or {}
    new_status = data.get('status')

    if new_status not in (STATUS_OPEN, STATUS_RESOLVED):
        return jsonify({'error': "Statut invalide."}), 400

    ticket.status = new_status
    db.session.commit()
    return jsonify(_serialize_ticket(ticket))


def _serialize_ticket(ticket, with_messages=False):
    data = {
        'id': ticket.id,
        'subject': ticket.subject,
        'category': ticket.category,
        'status': ticket.status,
        'author': ticket.author.username,
        'author_id': ticket.user_id,
        'created_at': ticket.created_at.isoformat(),
        'updated_at': ticket.updated_at.isoformat(),
        'message_count': len(ticket.messages),
    }
    if with_messages:
        data['messages'] = [_serialize_message(m) for m in ticket.messages]
    return data


def _serialize_message(msg):
    return {
        'id': msg.id,
        'body': msg.body,
        'author': msg.sender.username,
        'author_role': msg.sender.role,
        'is_own': msg.user_id == msg.sender.id,
        'created_at': msg.created_at.isoformat(),
    }
