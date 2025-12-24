from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import uuid

from config import Config
from models import db, User, VaultItem, ShareLink, AccessLog

app = Flask(__name__)
app.config.from_object(Config)

CORS(app)
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

# ---------------- AUTH ----------------

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    hashed = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

    user = User(email=data["email"], password=hashed)
    db.session.add(user)
    db.session.commit()

    return {"msg": "User registered"}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not bcrypt.check_password_hash(user.password, data["password"]):
        return {"msg": "Invalid credentials"}, 401

    token = create_access_token(identity=user.id)
    return {"access_token": token}

# ---------------- VAULT ----------------

@app.route("/vault", methods=["POST"])
@jwt_required()
def create_vault():
    user_id = get_jwt_identity()
    data = request.json

    vault = VaultItem(
        title=data["title"],
        content=data["content"],
        owner_id=user_id
    )
    db.session.add(vault)
    db.session.commit()

    return {"msg": "Vault created"}

@app.route("/vault", methods=["GET"])
@jwt_required()
def list_vaults():
    user_id = get_jwt_identity()
    vaults = VaultItem.query.filter_by(owner_id=user_id).all()

    return jsonify([
        {"id": v.id, "title": v.title, "created_at": v.created_at}
        for v in vaults
    ])

# ---------------- SHARE LINK ----------------

@app.route("/share/<int:vault_id>", methods=["POST"])
@jwt_required()
def create_share(vault_id):
    data = request.json
    link_id = uuid.uuid4().hex

    password = None
    if data.get("password"):
        password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

    share = ShareLink(
        id=link_id,
        vault_id=vault_id,
        expires_at=datetime.utcnow() + timedelta(hours=data["hours"]),
        remaining_views=data["views"],
        password=password
    )

    db.session.add(share)
    db.session.commit()

    return {"share_link": f"/access/{link_id}"}

# ---------------- PUBLIC ACCESS ----------------

@app.route("/access/<string:link_id>", methods=["POST"])
def access_vault(link_id):
    share = ShareLink.query.get(link_id)
    ip = request.remote_addr

    if not share or not share.active:
        log = AccessLog(vault_id=None, status="denied", ip=ip)
        db.session.add(log)
        db.session.commit()
        return {"msg": "Invalid link"}, 403

    if datetime.utcnow() > share.expires_at or share.remaining_views <= 0:
        share.active = False
        db.session.commit()
        return {"msg": "Link expired"}, 410

    if share.password:
        if not bcrypt.check_password_hash(share.password, request.json.get("password", "")):
            log = AccessLog(vault_id=share.vault_id, status="denied", ip=ip)
            db.session.add(log)
            db.session.commit()
            return {"msg": "Wrong password"}, 403

    share.remaining_views -= 1
    if share.remaining_views == 0:
        share.active = False

    vault = VaultItem.query.get(share.vault_id)

    log = AccessLog(vault_id=vault.id, status="allowed", ip=ip)
    db.session.add(log)
    db.session.commit()

    return {"title": vault.title, "content": vault.content}

# ---------------- LOGS ----------------

@app.route("/logs/<int:vault_id>")
@jwt_required()
def logs(vault_id):
    logs = AccessLog.query.filter_by(vault_id=vault_id).all()
    return jsonify([
        {"time": l.timestamp, "status": l.status, "ip": l.ip}
        for l in logs
    ])

if __name__ == "__main__":
    app.run(debug=True)
