"""
VaultX - Database Models
SQLAlchemy models for Users, Files, and Audit Logs.
"""
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(64), nullable=True, unique=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    files = db.relationship("File", backref="owner", lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True)

    # ---- Account lockout helpers ----
    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def register_failed_attempt(self):
        self.login_attempts = (self.login_attempts or 0) + 1
        if self.login_attempts >= MAX_LOGIN_ATTEMPTS:
            self.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None

    def is_reset_token_valid(self, token):
        if not self.reset_token or not self.reset_token_expires:
            return False
        if self.reset_token != token:
            return False
        return self.reset_token_expires > datetime.utcnow()

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)  # UUID.enc
    sha256_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(20), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=True, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "original_name": self.original_name,
            "sha256_hash": self.sha256_hash,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "is_encrypted": self.is_encrypted,
            "uploaded_at": self.uploaded_at.isoformat() if self.uploaded_at else None,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False)
    details = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # SUCCESS / FAILED
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


def log_event(db_session, action, status, user_id=None, details=None, ip_address=None, user_agent=None):
    """Helper to write an audit log entry. Never raises - logging must not break the app."""
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
        )
        db_session.add(entry)
        db_session.commit()
    except Exception:
        db_session.rollback()
