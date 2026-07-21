"""
VaultX - Secure Cloud Storage System with MFA and AES-256 Encryption
Final Year Project - Bachelor of Computer Science Security (BCSS)

Main Flask application: routes, authentication, MFA, and file endpoints.
"""
import os
import io
import uuid
import base64
import secrets as pysecrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, session, send_file, render_template,
    redirect, url_for
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import pyotp
import qrcode

from models import db, User, File, AuditLog, log_event
from encryption import (
    encrypt_file_bytes, decrypt_file_bytes, check_vault_status
)

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "encrypted_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(BASE_DIR), "templates"),
    static_folder=os.path.join(os.path.dirname(BASE_DIR), "static"),
)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", pysecrets.token_hex(32))

database_url = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'vaultx.db')}")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV", "development") == "production"

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

db.init_app(app)

allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
CORS(app, supports_credentials=True, origins=allowed_origins.split(",") if allowed_origins != "*" else "*")

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])

with app.app_context():
    db.create_all()

# ---------------------------------------------------------------------------
# File type policy
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg",
    "zip", "rar", "7z", "tar", "gz",
    "mp3", "mp4", "wav", "json", "xml", "md",
}
BLOCKED_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "ps1", "vbs", "php", "asp",
    "aspx", "jsp", "cgi", "dll", "msi", "apk",
}


def get_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def is_allowed_file(filename: str) -> bool:
    ext = get_extension(filename)
    if ext in BLOCKED_EXTENSIONS:
        return False
    return ext in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------
SPECIAL_CHARS = set("!@#$%^&*")


def validate_password(password: str):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least 1 uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least 1 lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least 1 number."
    if not any(c in SPECIAL_CHARS for c in password):
        return False, "Password must contain at least 1 special character (!@#$%^&*)."
    return True, ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"


def client_ua():
    return request.headers.get("User-Agent", "unknown")[:255]


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required."}), 401
        if not session.get("mfa_verified"):
            return jsonify({"error": "MFA verification required."}), 401
        return f(*args, **kwargs)
    return wrapper


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Resource not found."}), 404


@app.errorhandler(413)
def handle_413(e):
    return jsonify({"error": "File too large. Maximum 50MB"}), 413


@app.errorhandler(429)
def handle_429(e):
    return jsonify({"error": "Too many requests. Please wait."}), 429


@app.errorhandler(500)
def handle_500(e):
    db.session.rollback()
    return jsonify({"error": "Internal server error."}), 500


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if session.get("user_id") and session.get("mfa_verified"):
        return redirect(url_for("dashboard_page"))
    return redirect(url_for("login_page"))


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/mfa-setup")
def mfa_setup_page():
    return render_template("mfa_setup.html")


@app.route("/mfa-verify")
def mfa_verify_page():
    return render_template("mfa_verify.html")


@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")


@app.route("/reset-password")
def reset_password_page():
    return render_template("reset_password.html")


@app.route("/dashboard")
def dashboard_page():
    if not session.get("user_id") or not session.get("mfa_verified"):
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# Auth API - Registration
# ---------------------------------------------------------------------------
@app.route("/api/register", methods=["POST"])
@limiter.limit("10 per minute")
def api_register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400

    valid, message = validate_password(password)
    if not valid:
        return jsonify({"error": message}), 400

    if User.query.filter_by(email=email).first():
        log_event(db.session, "REGISTER", "FAILED", details=f"Duplicate email: {email}",
                   ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "An account with this email already exists."}), 409

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    totp_secret = pyotp.random_base32()

    user = User(
        name=name,
        email=email,
        password_hash=password_hash,
        totp_secret=totp_secret,
        mfa_enabled=False,
    )
    db.session.add(user)
    db.session.commit()

    log_event(db.session, "REGISTER", "SUCCESS", user_id=user.id,
              ip_address=client_ip(), user_agent=client_ua())

    # Build otpauth:// URI and generate a QR code as base64 PNG
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="VaultX")

    qr_img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    # Store pending user id in session until MFA setup is verified
    session["pending_user_id"] = user.id

    return jsonify({
        "message": "Registration successful. Please set up MFA.",
        "user_id": user.id,
        "qr_code": f"data:image/png;base64,{qr_base64}",
        "totp_secret": totp_secret,
        "provisioning_uri": provisioning_uri,
    }), 201


@app.route("/api/mfa/setup/verify", methods=["POST"])
@limiter.limit("10 per minute")
def api_mfa_setup_verify():
    data = request.get_json(silent=True) or {}
    otp_code = (data.get("otp_code") or "").strip()
    user_id = session.get("pending_user_id") or data.get("user_id")

    if not user_id:
        return jsonify({"error": "No pending MFA setup found. Please register again."}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(otp_code, valid_window=1):
        log_event(db.session, "MFA_SETUP_VERIFY", "FAILED", user_id=user.id,
                   ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "Invalid OTP code. Please try again."}), 401

    user.mfa_enabled = True
    db.session.commit()

    session.pop("pending_user_id", None)
    session.permanent = True
    session["user_id"] = user.id
    session["mfa_verified"] = True

    log_event(db.session, "MFA_SETUP_VERIFY", "SUCCESS", user_id=user.id,
              ip_address=client_ip(), user_agent=client_ua())

    return jsonify({"message": "MFA enabled successfully.", "user": user.to_dict()}), 200


# ---------------------------------------------------------------------------
# Auth API - Login (2-step)
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()

    if not user:
        log_event(db.session, "LOGIN_STEP1", "FAILED", details=f"Unknown email: {email}",
                   ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "Invalid email or password."}), 401

    if user.is_locked():
        log_event(db.session, "LOGIN_STEP1", "FAILED", user_id=user.id,
                   details="Account locked", ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "Account is locked due to too many failed attempts. "
                                  "Try again in 15 minutes."}), 423

    if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        user.register_failed_attempt()
        db.session.commit()
        log_event(db.session, "LOGIN_STEP1", "FAILED", user_id=user.id,
                   details="Bad password", ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "Invalid email or password."}), 401

    # Password OK - reset attempts, but do NOT fully log in yet (MFA pending)
    user.reset_login_attempts()
    db.session.commit()

    session["pending_login_user_id"] = user.id
    session["mfa_verified"] = False

    log_event(db.session, "LOGIN_STEP1", "SUCCESS", user_id=user.id,
              ip_address=client_ip(), user_agent=client_ua())

    return jsonify({"message": "Password verified. Please enter your MFA code.",
                     "mfa_required": True, "user_id": user.id}), 200


@app.route("/api/login/mfa", methods=["POST"])
@limiter.limit("10 per minute")
def api_login_mfa():
    data = request.get_json(silent=True) or {}
    otp_code = (data.get("otp_code") or "").strip()
    user_id = session.get("pending_login_user_id") or data.get("user_id")

    if not user_id:
        return jsonify({"error": "No pending login found. Please log in again."}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    if user.is_locked():
        return jsonify({"error": "Account is locked. Try again later."}), 423

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(otp_code, valid_window=1):
        user.register_failed_attempt()
        db.session.commit()
        log_event(db.session, "LOGIN_STEP2_MFA", "FAILED", user_id=user.id,
                   ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "Invalid MFA code."}), 401

    user.reset_login_attempts()
    db.session.commit()

    session.pop("pending_login_user_id", None)
    session.permanent = True
    session["user_id"] = user.id
    session["mfa_verified"] = True

    log_event(db.session, "LOGIN_STEP2_MFA", "SUCCESS", user_id=user.id,
              ip_address=client_ip(), user_agent=client_ua())

    return jsonify({"message": "Login successful.", "user": user.to_dict()}), 200


# ---------------------------------------------------------------------------
# Auth API - Forgot / Reset Password
# ---------------------------------------------------------------------------
RESET_TOKEN_MINUTES = 15


@app.route("/api/auth/forgot-password", methods=["POST"])
@limiter.limit("5 per minute")
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    generic_response = {
        "message": "If an account exists for that email, a password reset link has been generated."
    }

    if not email:
        return jsonify({"error": "Email is required."}), 400

    user = User.query.filter_by(email=email).first()

    # Always return the same generic message whether or not the account exists,
    # so this endpoint can't be used to enumerate registered emails.
    if not user:
        log_event(db.session, "FORGOT_PASSWORD", "FAILED", details=f"Unknown email: {email}",
                   ip_address=client_ip(), user_agent=client_ua())
        return jsonify(generic_response), 200

    token = pysecrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expires = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)
    db.session.commit()

    log_event(db.session, "FORGOT_PASSWORD", "SUCCESS", user_id=user.id,
               ip_address=client_ip(), user_agent=client_ua())

    reset_link = f"{request.host_url.rstrip('/')}/reset-password?token={token}"

    # NOTE: VaultX has no SMTP/email service configured. In a production deployment,
    # reset_link would be emailed to the user instead of being returned in the API
    # response. For local development and FYP demonstration purposes, the link is
    # returned directly so the reset flow can be tested end-to-end without a mail server.
    generic_response["reset_link"] = reset_link
    generic_response["expires_in_minutes"] = RESET_TOKEN_MINUTES
    return jsonify(generic_response), 200


@app.route("/api/auth/reset-password", methods=["POST"])
@limiter.limit("10 per minute")
def api_reset_password():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("new_password") or ""

    if not token:
        return jsonify({"error": "Reset token is missing."}), 400

    valid, message = validate_password(new_password)
    if not valid:
        return jsonify({"error": message}), 400

    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.is_reset_token_valid(token):
        log_event(db.session, "RESET_PASSWORD", "FAILED", details="Invalid or expired token",
                   ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "This reset link is invalid or has expired. Please request a new one."}), 400

    user.password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    user.reset_token = None
    user.reset_token_expires = None
    user.reset_login_attempts()
    db.session.commit()

    log_event(db.session, "RESET_PASSWORD", "SUCCESS", user_id=user.id,
               ip_address=client_ip(), user_agent=client_ua())

    return jsonify({"message": "Password reset successfully. You can now sign in."}), 200


@app.route("/api/logout", methods=["POST"])
def api_logout():
    user_id = session.get("user_id")
    session.clear()
    if user_id:
        log_event(db.session, "LOGOUT", "SUCCESS", user_id=user_id,
                   ip_address=client_ip(), user_agent=client_ua())
    return jsonify({"message": "Logged out successfully."}), 200


@app.route("/api/me", methods=["GET"])
@login_required
def api_me():
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"user": user.to_dict()}), 200


# ---------------------------------------------------------------------------
# Files API
# ---------------------------------------------------------------------------
@app.route("/api/files", methods=["GET"])
@login_required
def api_list_files():
    user = get_current_user()
    files = File.query.filter_by(user_id=user.id).order_by(File.uploaded_at.desc()).all()
    return jsonify({"files": [f.to_dict() for f in files]}), 200


@app.route("/api/files/upload", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def api_upload_file():
    user = get_current_user()

    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    uploaded = request.files["file"]
    filename = uploaded.filename or ""

    if filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not is_allowed_file(filename):
        ext = get_extension(filename)
        log_event(db.session, "FILE_UPLOAD", "FAILED", user_id=user.id,
                   details=f"Blocked file type: .{ext}", ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": f"File type '.{ext}' is not allowed."}), 400

    raw_bytes = uploaded.read()
    if len(raw_bytes) > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "File too large. Maximum 50MB"}), 413

    try:
        encrypted_blob, sha256_hash = encrypt_file_bytes(raw_bytes)
    except Exception as e:
        log_event(db.session, "FILE_UPLOAD", "FAILED", user_id=user.id,
                   details=f"Encryption error: {e}", ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "Encryption failed. Please try again."}), 500

    stored_name = f"{uuid.uuid4()}.enc"
    stored_path = os.path.join(STORAGE_DIR, stored_name)
    with open(stored_path, "wb") as f:
        f.write(encrypted_blob)

    file_record = File(
        user_id=user.id,
        original_name=filename,
        stored_name=stored_name,
        sha256_hash=sha256_hash,
        file_size=len(raw_bytes),
        file_type=get_extension(filename),
        is_encrypted=True,
    )
    db.session.add(file_record)
    db.session.commit()

    log_event(db.session, "FILE_UPLOAD", "SUCCESS", user_id=user.id,
               details=f"Uploaded {filename}", ip_address=client_ip(), user_agent=client_ua())

    return jsonify({"message": "File uploaded and encrypted successfully.",
                     "file": file_record.to_dict()}), 201


@app.route("/api/files/<int:file_id>/download", methods=["GET"])
@login_required
def api_download_file(file_id):
    user = get_current_user()
    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()

    if not file_record:
        log_event(db.session, "FILE_DOWNLOAD", "FAILED", user_id=user.id,
                   details=f"File {file_id} not found or not owned", ip_address=client_ip(),
                   user_agent=client_ua())
        return jsonify({"error": "File not found."}), 404

    stored_path = os.path.join(STORAGE_DIR, file_record.stored_name)
    if not os.path.exists(stored_path):
        return jsonify({"error": "File data missing on server."}), 404

    with open(stored_path, "rb") as f:
        blob = f.read()

    try:
        plaintext, recomputed_hash = decrypt_file_bytes(blob)
    except Exception as e:
        log_event(db.session, "FILE_DOWNLOAD", "FAILED", user_id=user.id,
                   details=f"Decryption error: {e}", ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "Decryption failed."}), 500

    if recomputed_hash != file_record.sha256_hash:
        log_event(db.session, "FILE_DOWNLOAD", "FAILED", user_id=user.id,
                   details=f"Integrity check FAILED for {file_record.original_name}",
                   ip_address=client_ip(), user_agent=client_ua())
        return jsonify({"error": "File integrity check failed. The file may be corrupted."}), 500

    log_event(db.session, "FILE_DOWNLOAD", "SUCCESS", user_id=user.id,
               details=f"Downloaded {file_record.original_name}", ip_address=client_ip(),
               user_agent=client_ua())

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file_record.original_name,
        mimetype="application/octet-stream",
    )


@app.route("/api/files/<int:file_id>", methods=["DELETE"])
@login_required
def api_delete_file(file_id):
    user = get_current_user()
    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()

    if not file_record:
        return jsonify({"error": "File not found."}), 404

    stored_path = os.path.join(STORAGE_DIR, file_record.stored_name)
    if os.path.exists(stored_path):
        os.remove(stored_path)

    original_name = file_record.original_name
    db.session.delete(file_record)
    db.session.commit()

    log_event(db.session, "FILE_DELETE", "SUCCESS", user_id=user.id,
               details=f"Deleted {original_name}", ip_address=client_ip(), user_agent=client_ua())

    return jsonify({"message": "File deleted successfully."}), 200


# ---------------------------------------------------------------------------
# Audit log + Vault status API
# ---------------------------------------------------------------------------
@app.route("/api/logs", methods=["GET"])
@login_required
def api_logs():
    user = get_current_user()
    logs = (
        AuditLog.query.filter_by(user_id=user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return jsonify({"logs": [log.to_dict() for log in logs]}), 200


@app.route("/api/vault/status", methods=["GET"])
@login_required
def api_vault_status():
    return jsonify(check_vault_status()), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_ENV") == "development")
