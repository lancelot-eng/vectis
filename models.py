from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

# Rôles possibles pour un utilisateur
ROLE_USER = 'user'
ROLE_MODERATOR = 'moderator'
ROLE_ADMIN = 'admin'

# Statuts possibles pour un ticket
STATUS_OPEN = 'open'
STATUS_RESOLVED = 'resolved'


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default=ROLE_USER)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Marqueur de suppression (soft-delete) pour respecter la politique
    # de conservation de 6 mois après suppression du compte.
    deleted_at = db.Column(db.DateTime, nullable=True)

    tickets = db.relationship('Ticket', backref='author', lazy=True,
                               foreign_keys='Ticket.user_id')
    messages = db.relationship('TicketMessage', backref='sender', lazy=True)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    @property
    def is_admin(self):
        return self.role == ROLE_ADMIN

    @property
    def is_moderator(self):
        return self.role in (ROLE_MODERATOR, ROLE_ADMIN)

    @property
    def is_deleted(self):
        return self.deleted_at is not None

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Ticket(db.Model):
    __tablename__ = 'tickets'

    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(60), nullable=False, default='Autre')
    status = db.Column(db.String(20), nullable=False, default=STATUS_OPEN)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    messages = db.relationship('TicketMessage', backref='ticket', lazy=True,
                                order_by='TicketMessage.created_at',
                                cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Ticket #{self.id} {self.subject}>'


class TicketMessage(db.Model):
    __tablename__ = 'ticket_messages'

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message #{self.id} on Ticket #{self.ticket_id}>'
