from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ShareLink(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    vault_id = db.Column(db.Integer, db.ForeignKey("vault_item.id"))
    expires_at = db.Column(db.DateTime)
    remaining_views = db.Column(db.Integer)
    password = db.Column(db.String(200), nullable=True)
    active = db.Column(db.Boolean, default=True)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))
    ip = db.Column(db.String(50))
