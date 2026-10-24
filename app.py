import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template_string,
    request, send_file, url_for
)
from flask_login import (
    LoginManager, UserMixin, current_user, login_required,
    login_user, logout_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from markupsafe import Markup, escape
from sqlalchemy import or_, select
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "instance"
UPLOAD_DIR = DATA_DIR / "documents"
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "TRUSTVAULT_SECRET_KEY", secrets.token_hex(32)
)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + (DATA_DIR / "trustvault.db").as_posix()
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

csrf = CSRFProtect(app)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".docx"}


# ---------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    owner = db.relationship("User", backref="documents")


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("document.id"), nullable=False
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    can_read = db.Column(db.Boolean, default=True, nullable=False)
    can_edit = db.Column(db.Boolean, default=False, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id"),
    )


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(80), nullable=False)
    document_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


# ---------------------------------------------------------------------
# Authentication and access-control helpers
# ---------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def record_event(action, document_id=None, details=""):
    actor_id = current_user.id if current_user.is_authenticated else None
    db.session.add(
        AuditEvent(
            actor_id=actor_id,
            action=action,
            document_id=document_id,
            details=str(details)[:500],
        )
    )
    db.session.commit()


def get_permission(document, user_id):
    return db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == user_id,
        )
    )


def can_read(document):
    if not current_user.is_authenticated:
        return False
    if document.owner_id == current_user.id:
        return True
    permission = get_permission(document, current_user.id)
    return bool(permission and permission.can_read)


def can_edit(document):
    if not current_user.is_authenticated:
        return False
    if document.owner_id == current_user.id:
        return True
    permission = get_permission(document, current_user.id)
    return bool(permission and permission.can_edit)


# ---------------------------------------------------------------------
# Shared visual styles and dashboard template
# ---------------------------------------------------------------------
STYLE = """
<style>
:root {
  --navy:#14213d; --navy2:#20365f; --blue:#4563e9; --blue-dark:#344fd0;
  --bg:#f5f7fc; --surface:#fff; --text:#202b40; --muted:#748096;
  --border:#e5e9f2; --green:#137a4b; --green-bg:#e9f8f0;
  --red:#b42318; --red-bg:#fff0ef;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
 font-family:Inter,"Segoe UI",Arial,sans-serif;line-height:1.55}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
.topbar{background:#fff;border-bottom:1px solid var(--border);
 padding:17px 5%;display:flex;align-items:center;justify-content:space-between;gap:18px}
.brand{display:flex;align-items:center;gap:11px;color:var(--navy);
 font-size:23px;font-weight:800;letter-spacing:-.6px;text-decoration:none}
.brand-icon{display:grid;place-items:center;width:42px;height:42px;
 background:#eaf0ff;border-radius:13px;font-size:22px}
.navlinks{display:flex;align-items:center;gap:18px;flex-wrap:wrap;font-size:14px;font-weight:650}
.navlinks a{color:#526078}
.navlinks .logout{color:var(--blue)}
.shell{max-width:1120px;margin:34px auto;padding:0 22px 50px}
.hero{padding:30px 32px;border-radius:20px;color:#fff;
 background:radial-gradient(ellipse at top right,#344d8d 0%,transparent 55%),
 linear-gradient(135deg,var(--navy),var(--navy2));
 box-shadow:0 16px 38px rgba(20,33,61,.12);margin-bottom:24px}
.hero h1{font-size:clamp(27px,4vw,36px);line-height:1.2;letter-spacing:-1px;margin:0 0 8px}
.hero p{margin:7px 0;color:#d6e0f7}
.eyebrow{font-size:12px;letter-spacing:1.1px;text-transform:uppercase;font-weight:750;color:#dce5ff}
.grid{display:grid;grid-template-columns:1fr;gap:22px}
.panel{background:var(--surface);padding:26px;border:1px solid var(--border);
 border-radius:17px;box-shadow:0 7px 22px rgba(25,42,75,.035);min-width:0}
.panel h2{margin:0 0 7px;font-size:20px;color:var(--navy);letter-spacing:-.35px}
.panel-intro{color:var(--muted);font-size:14px;margin:0 0 19px}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
input,button{font:inherit;max-width:100%}
input:not([type=checkbox]):not([type=file]){padding:11px 13px;border:1px solid #d8dfeb;
 border-radius:9px;background:#fff;color:var(--text);outline:none;min-width:0}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(69,99,233,.12)}
input[type=file]{display:block;width:100%;padding:13px;border:1px dashed #bdc9dc;
 border-radius:10px;background:#f8faff;margin:10px 0 14px}
input[type=checkbox]{accent-color:var(--blue);margin-right:5px}
button,.button{display:inline-block;border:0;border-radius:9px;padding:11px 16px;
 background:var(--blue);color:#fff;font-weight:700;cursor:pointer;text-decoration:none}
button:hover,.button:hover{background:var(--blue-dark);text-decoration:none}
.button.secondary{background:#edf1ff;color:#3049bd}
.button.danger{background:#fff0ef;color:#b42318}
form{margin:0}
.small{display:block;color:var(--muted);font-size:13px;margin-top:9px}
.notice{padding:13px 15px;margin:0 0 17px;border-radius:10px;
 background:var(--green-bg);color:var(--green);border:1px solid #c9ead8;font-size:14px}
.notice.error{background:var(--red-bg);color:var(--red);border-color:#f4d0cc}
.search{display:flex;gap:9px;flex-wrap:wrap;margin:16px 0}
.search input{flex:1;width:240px}
.doc-list{list-style:none;padding:0;margin:17px 0 0;display:grid;gap:13px}
.doc-card{border:1px solid var(--border);border-radius:13px;padding:18px;background:#fcfdff;min-width:0}
.doc-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
.doc-name{font-weight:750;color:var(--navy);overflow-wrap:anywhere}
.meta{font-size:13px;color:var(--muted);margin-top:5px}
.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}
.manage{border-top:1px solid var(--border);padding-top:14px;margin-top:15px}
.manage-title{font-size:13px;font-weight:750;color:#48556c;margin-bottom:8px}
.manage input:not([type=checkbox]){width:180px}
.empty{padding:28px 16px;text-align:center;border:1px dashed #ccd5e4;
 border-radius:12px;color:var(--muted);background:#fafbfe}
footer{text-align:center;color:#8a94a7;font-size:12px;padding:22px}
@media(min-width:850px){.grid.two{grid-template-columns:.82fr 1.18fr}}
@media(max-width:640px){.topbar{padding:14px 17px;align-items:flex-start}
 .navlinks{gap:10px}.shell{margin:20px auto;padding:0 13px 32px}
 .hero,.panel{padding:21px 17px;border-radius:14px}
 .doc-card{padding:14px}.search input{width:100%;flex-basis:100%}
 .manage input:not([type=checkbox]){width:100%}.brand{font-size:20px}}
</style>
"""

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrustVault | Secure document workspace</title>
""" + STYLE + """
</head>
<body>
<header class="topbar">
  <a class="brand" href="{{ url_for('home') }}"><span class="brand-icon">🔐</span><span>TrustVault</span></a>
  <nav class="navlinks">
  {% if current_user.is_authenticated %}
    <a href="{{ url_for('home') }}">Documents</a>
    <a href="{{ url_for('audit') }}">Audit activity</a>
    <a class="logout" href="{{ url_for('logout') }}">Log out</a>
  {% else %}
    <a href="{{ url_for('login') }}">Sign in</a>
    <a href="{{ url_for('register') }}">Create account</a>
  {% endif %}
  </nav>
</header>
<div class="shell">
  {% for message in get_flashed_messages() %}
    <div class="notice">{{ message }}</div>
  {% endfor %}
  <section class="hero">
    <div class="eyebrow">Your secure workspace</div>
    <h1>Documents protected.<br>Trust built.</h1>
    <p>Manage your files, control access, and keep track of document activity.</p>
    {% if current_user.is_authenticated %}
      <p>Signed in as <strong>{{ current_user.username }}</strong></p>
    {% endif %}
  </section>

  {% if current_user.is_authenticated %}
  <div class="grid two">
    <section class="panel">
      <h2>Upload a document</h2>
      <p class="panel-intro">Add a file to your private workspace.</p>
      <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="file" name="document" required>
        <button type="submit">↑ Upload document</button>
      </form>
      <span class="small">PDF, TXT, PNG, JPG, JPEG, DOCX · Maximum 10 MB</span>
    </section>

    <section class="panel">
      <h2>Your documents</h2>
      <p class="panel-intro">Files you own and files shared with you.</p>
      <form class="search" method="get" action="{{ url_for('home') }}">
        <input type="search" name="q" placeholder="Search by filename..." value="{{ search_query }}">
        <button type="submit">Search</button>
        <a class="button secondary" href="{{ url_for('home') }}">Clear</a>
      </form>
      {% if documents %}
      <ul class="doc-list">
      {% for doc in documents %}
        <li class="doc-card">
          <div class="doc-head">
            <div>
              <div class="doc-name">📄 {{ doc.original_name }}</div>
              <div class="meta">Owner: {{ doc.owner.username }} · Added {{ doc.created_at.strftime('%Y-%m-%d') if doc.created_at else '' }}</div>
            </div>
            <a class="button" href="{{ url_for('download', document_id=doc.id) }}">Download</a>
          </div>
          {% if doc.owner_id == current_user.id %}
          <div class="manage">
            <div class="manage-title">Manage document access</div>
            <form method="post" action="{{ url_for('share', document_id=doc.id) }}" class="row">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <input name="username" placeholder="Username to share with" required minlength="3" maxlength="80">
              <label><input type="checkbox" name="can_read" checked> Read</label>
              <label><input type="checkbox" name="can_edit"> Edit</label>
              <button type="submit">Grant access</button>
            </form>
            <form method="post" action="{{ url_for('revoke', document_id=doc.id) }}" class="row" style="margin-top:10px">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <input name="username" placeholder="Username to revoke" required minlength="3" maxlength="80">
              <button class="button danger" type="submit">Revoke access</button>
            </form>
          </div>
          {% endif %}
        </li>
      {% endfor %}
      </ul>
      {% else %}
        <div class="empty">No documents found.<br><span class="small">Upload a document or clear your search.</span></div>
      {% endif %}
    </section>
  </div>
  {% else %}
    <section class="panel">
      <h2>Keep your documents under control</h2>
      <p class="panel-intro">Sign in to upload files, manage sharing permissions, and view your activity history.</p>
      <div class="row">
        <a class="button" href="{{ url_for('login') }}">Sign in</a>
        <a class="button secondary" href="{{ url_for('register') }}">Create an account</a>
      </div>
    </section>
  {% endif %}
</div>
<footer>TrustVault · Secure document sharing with accountability</footer>
</body>
</html>
"""

AUTH_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ heading }} | TrustVault</title>
""" + STYLE + """
<style>
.auth-main{min-height:calc(100vh - 150px);display:grid;place-items:center;padding:38px 18px}
.auth-layout{width:100%;max-width:960px;display:grid;grid-template-columns:1fr .9fr;
 background:#fff;border:1px solid var(--border);border-radius:23px;overflow:hidden;
 box-shadow:0 24px 70px rgba(25,39,75,.09)}
.welcome{padding:52px 40px;color:white;background:
 radial-gradient(ellipse at top right,#344d8d 0%,transparent 55%),
 linear-gradient(145deg,#101b35,#1c2d55);display:flex;flex-direction:column;justify-content:center}
.welcome .eyebrow{display:inline-block;align-self:flex-start;padding:7px 11px;
 border:1px solid rgba(255,255,255,.2);border-radius:30px;color:#dce5ff;font-size:11px}
.welcome h1{margin:24px 0 14px;font-size:clamp(30px,4vw,42px);line-height:1.15;letter-spacing:-1.3px}
.welcome p{color:#d1dbf3;line-height:1.8;font-size:14px}
.feature{display:flex;gap:12px;align-items:center;margin-top:19px;color:#f2f5ff;font-size:13px}
.feature-icon{display:grid;place-items:center;width:35px;height:35px;flex-shrink:0;border-radius:10px;background:rgba(255,255,255,.12)}
.form-side{padding:48px 36px;display:flex;flex-direction:column;justify-content:center}
.form-side h2{margin:0 0 8px;font-size:29px;letter-spacing:-.8px;color:var(--navy)}
.subtitle{margin:0 0 25px;color:var(--muted);font-size:14px;line-height:1.7}
.field{display:block;margin-bottom:17px}
.field span{display:block;margin-bottom:7px;color:#354158;font-size:13px;font-weight:700}
.field input{width:100%;padding:13px 14px;border:1px solid #dce2ed;border-radius:10px;outline:none;background:white;color:var(--text);font:inherit;font-size:14px}
.field input:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(69,99,233,.12)}
.submit-btn{width:100%;padding:14px;border:0;border-radius:10px;background:var(--blue);color:white;font:inherit;font-weight:750;cursor:pointer}
.submit-btn:hover{background:var(--blue-dark)}
.bottom-note{margin:22px 0 0;text-align:center;color:var(--muted);font-size:13px;line-height:1.8}
.bottom-note a{font-weight:750}
@media(max-width:700px){.auth-layout{max-width:440px;grid-template-columns:1fr;border-radius:17px}
 .welcome{padding:28px 24px}.welcome h1{font-size:29px;margin-top:17px}
 .feature{margin-top:12px}.form-side{padding:30px 24px}.form-side h2{font-size:26px}}
</style>
</head>
<body>
<header class="topbar">
  <a class="brand" href="{{ url_for('home') }}"><span class="brand-icon">🔐</span><span>TrustVault</span></a>
  <a href="{{ url_for('home') }}">Back to home ↗</a>
</header>
<main class="auth-main">
  <div class="auth-layout">
    <section class="welcome">
      <span class="eyebrow">YOUR SECURE WORKSPACE</span>
      <h1>Documents protected.<br>Trust built.</h1>
      <p>A secure space to manage documents, control access, and keep track of important activity.</p>
      <div class="feature"><span class="feature-icon">🛡️</span><span>Access permissions for your documents</span></div>
      <div class="feature"><span class="feature-icon">📋</span><span>Activity tracking and audit history</span></div>
    </section>
    <section class="form-side">
      <h2>{{ heading }}</h2>
      <p class="subtitle">
      {% if heading == "Login" %}Welcome back. Sign in to access your secure workspace.
      {% else %}Create your account to get started with TrustVault.{% endif %}
      </p>
      {% for message in get_flashed_messages() %}
        <div class="notice error">{{ message }}</div>
      {% endfor %}
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label class="field"><span>Username</span>
          <input name="username" autocomplete="username" placeholder="Enter your username" required minlength="3" maxlength="80">
        </label>
        <label class="field"><span>Password</span>
          <input type="password" name="password" autocomplete="{% if heading == 'Login' %}current-password{% else %}new-password{% endif %}" placeholder="Enter your password" required minlength="8">
        </label>
        <button class="submit-btn" type="submit">{{ heading }} →</button>
      </form>
      <p class="bottom-note">
      {% if heading == "Login" %}New to TrustVault? <a href="{{ url_for('register') }}">Create an account</a>
      {% else %}Already have an account? <a href="{{ url_for('login') }}">Sign in</a>{% endif %}
      <br><br>Your documents. Your permissions. Your control.
      </p>
    </section>
  </div>
</main>
<footer>TrustVault · Secure document sharing with accountability</footer>
</body>
</html>
"""


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------
@app.route("/")
def home():
    search_query = request.args.get("q", "").strip()
    documents = []

    if current_user.is_authenticated:
        owned = db.session.scalars(
            select(Document).where(Document.owner_id == current_user.id)
        ).all()

        shared_ids = db.session.scalars(
            select(Permission.document_id).where(
                Permission.user_id == current_user.id,
                Permission.can_read.is_(True),
            )
        ).all()

        shared = (
            db.session.scalars(
                select(Document).where(Document.id.in_(shared_ids))
            ).all()
            if shared_ids else []
        )

        documents = list({doc.id: doc for doc in owned + shared}.values())
        if search_query:
            documents = [
                doc for doc in documents
                if search_query.casefold() in doc.original_name.casefold()
            ]
        documents.sort(key=lambda doc: doc.id, reverse=True)

    return render_template_string(
        PAGE, documents=documents, search_query=search_query
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated and request.method == "GET":
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 80 or len(password) < 8:
            flash("Username must have 3–80 characters and password at least 8.")
        elif db.session.scalar(select(User).where(User.username == username)):
            flash("That username is already registered.")
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            record_event("register", details="Account created")
            flash("Welcome to TrustVault.")
            return redirect(url_for("home"))

    return render_template_string(AUTH_PAGE, heading="Create account")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated and request.method == "GET":
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.session.scalar(select(User).where(User.username == username))

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            record_event("login")
            return redirect(url_for("home"))

        record_event("login_failed", details=f"Failed login for {username[:80]}")
        flash("Invalid username or password.")

    return render_template_string(AUTH_PAGE, heading="Login")


@app.route("/logout")
@login_required
def logout():
    record_event("logout")
    logout_user()
    flash("You have been signed out.")
    return redirect(url_for("home"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("document")
    if not uploaded or not uploaded.filename:
        flash("Choose a file first.")
        return redirect(url_for("home"))

    original_name = secure_filename(uploaded.filename)
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_EXTENSIONS:
        flash("That file type is not allowed.")
        record_event("upload_denied", details="Disallowed file extension")
        return redirect(url_for("home"))

    stored_name = secrets.token_hex(24) + extension
    destination = UPLOAD_DIR / stored_name

    try:
        uploaded.save(destination)
        document = Document(
            original_name=original_name,
            stored_name=stored_name,
            owner_id=current_user.id,
        )
        db.session.add(document)
        db.session.commit()
    except Exception:
        db.session.rollback()
        destination.unlink(missing_ok=True)
        app.logger.exception("Document upload failed")
        flash("Upload failed. Please try again.")
        return redirect(url_for("home"))

    record_event("upload", document.id, f"Uploaded {original_name}")
    flash("Document uploaded successfully.")
    return redirect(url_for("home"))


@app.route("/download/<int:document_id>")
@login_required
def download(document_id):
    document = db.session.get(Document, document_id)
    if document is None:
        record_event("download_denied", document_id, "Document not found")
        abort(404)

    if not can_read(document):
        record_event("download_denied", document.id, "Read access denied")
        abort(403)

    file_path = UPLOAD_DIR / document.stored_name
    if not file_path.is_file():
        record_event("download_failed", document.id, "Stored file missing")
        abort(404)

    record_event("download", document.id, f"Downloaded {document.original_name}")
    return send_file(
        file_path,
        as_attachment=True,
        download_name=document.original_name,
    )


@app.route("/share/<int:document_id>", methods=["POST"])
@login_required
def share(document_id):
    document = db.session.get(Document, document_id)
    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        record_event("permission_grant_denied", document.id, "Only owner may grant access")
        abort(403)

    username = request.form.get("username", "").strip()
    target = db.session.scalar(select(User).where(User.username == username))

    if target is None:
        flash("Username not found.")
        return redirect(url_for("home"))

    if target.id == current_user.id:
        flash("You already own this document.")
        return redirect(url_for("home"))

    can_read_value = request.form.get("can_read") == "on"
    can_edit_value = request.form.get("can_edit") == "on"

    permission = get_permission(document, target.id)
    if permission is None:
        permission = Permission(
            document_id=document.id,
            user_id=target.id,
            can_read=can_read_value or can_edit_value,
            can_edit=can_edit_value,
        )
        db.session.add(permission)
    else:
        permission.can_read = can_read_value or can_edit_value
        permission.can_edit = can_edit_value

    db.session.commit()
    record_event(
        "permission_granted", document.id,
        f"Access updated for user {target.id}; read={permission.can_read}; edit={permission.can_edit}",
    )
    flash("Document permissions updated.")
    return redirect(url_for("home"))


@app.route("/revoke/<int:document_id>", methods=["POST"])
@login_required
def revoke(document_id):
    document = db.session.get(Document, document_id)
    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        record_event("revoke_denied", document.id, "Only the owner may revoke access")
        abort(403)

    username = request.form.get("username", "").strip()
    target = db.session.scalar(select(User).where(User.username == username))

    if target is None:
        flash("Username not found.")
        return redirect(url_for("home"))

    permission = get_permission(document, target.id)
    if permission is not None:
        db.session.delete(permission)
        db.session.commit()
        record_event("permission_revoked", document.id, f"Access revoked for user {target.id}")
        flash("Access revoked.")
    else:
        flash("That user does not have access to this document.")
    return redirect(url_for("home"))


@app.route("/audit")
@login_required
def audit():
    events = db.session.scalars(
        select(AuditEvent)
        .outerjoin(Document, AuditEvent.document_id == Document.id)
        .where(
            or_(
                AuditEvent.actor_id == current_user.id,
                Document.owner_id == current_user.id,
            )
        )
        .order_by(AuditEvent.id.desc())
        .limit(200)
    ).all()

    rows = "".join(
        (
            Markup("<li class='doc-card'><strong>")
            + escape(str(event.action))
            + Markup("</strong><div class='meta'>")
            + escape(str(event.created_at))
            + Markup("</div><div>")
            + escape(event.details or "")
            + Markup("</div></li>")
        )
        for event in events
    )

    return render_template_string(
        """
        <!doctype html><html lang="en"><head>
        <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Audit activity | TrustVault</title>
        """ + STYLE + """
        </head><body>
        <header class="topbar">
          <a class="brand" href="{{ url_for('home') }}"><span class="brand-icon">🔐</span><span>TrustVault</span></a>
          <nav class="navlinks"><a href="{{ url_for('home') }}">Documents</a><a href="{{ url_for('logout') }}">Log out</a></nav>
        </header>
        <main class="shell">
          <section class="hero"><div class="eyebrow">Security history</div>
          <h1>Audit activity</h1><p>Recent events visible to your account.</p></section>
          <section class="panel"><h2>Recent events</h2>
          {% if rows %}<ul class="doc-list">{{ rows|safe }}</ul>
          {% else %}<div class="empty">No audit events available yet.</div>{% endif %}
          </section>
        </main><footer>TrustVault · Secure document sharing with accountability</footer>
        </body></html>
        """,
        rows=rows,
    )


@app.errorhandler(403)
def forbidden(_error):
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Access denied</title>"
        + STYLE
        + "</head><body><main class='shell'><section class='panel'><h1>Access denied</h1>"
        "<p>You do not have permission to access this resource.</p>"
        "<a class='button' href='/'>Back to TrustVault</a></section></main></body></html>",
        403,
    )


@app.errorhandler(413)
def file_too_large(_error):
    flash("The selected file is larger than the 10 MB limit.")
    return redirect(url_for("home"))


@app.before_request
def initialize_database():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
