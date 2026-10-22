
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
from markupsafe import escape
from sqlalchemy import or_, select
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


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
        db.DateTime, default=lambda: datetime.now(timezone.utc)
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
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


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


def can_read(document):
    if not current_user.is_authenticated:
        return False

    if document.owner_id == current_user.id:
        return True

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == current_user.id,
        )
    )
    return bool(permission and permission.can_read)


def can_edit(document):
    if not current_user.is_authenticated:
        return False

    if document.owner_id == current_user.id:
        return True

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == current_user.id,
        )
    )
    return bool(permission and permission.can_edit)


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrustVault</title>
<style>
body {
    font-family: Arial, sans-serif;
    max-width: 850px;
    margin: 40px auto;
    padding: 0 18px;
    background: #f4f7fb;
    color: #172033;
}
header, .panel {
    background: white;
    padding: 22px;
    border-radius: 12px;
    margin-bottom: 18px;
}
a { color: #175cd3; }
input, button { padding: 10px; margin: 5px 0; max-width: 100%; }
button {
    cursor: pointer;
    background: #175cd3;
    color: white;
    border: 0;
    border-radius: 6px;
}
li { margin: 12px 0; }
.message { padding: 10px; background: #e9f7ed; border-radius: 6px; }
small { color: #555; }
</style>
</head>
<body>
<header>
<h1>🔐 TrustVault</h1>
<p>Secure document sharing with accountability</p>
{% if current_user.is_authenticated %}
<p>
Signed in as <b>{{ current_user.username }}</b> |
<a href="{{ url_for('logout') }}">Log out</a> |
<a href="{{ url_for('audit') }}">My audit events</a>
</p>
{% else %}
<a href="{{ url_for('login') }}">Login</a> |
<a href="{{ url_for('register') }}">Create account</a>
{% endif %}
</header>

{% for message in get_flashed_messages() %}
<p class="message">{{ message }}</p>
{% endfor %}

{% if current_user.is_authenticated %}
<section class="panel">
<h2>Upload a document</h2>
<form method="post" action="{{ url_for('upload') }}"
      enctype="multipart/form-data">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<input type="file" name="document" required>
<button type="submit">Upload securely</button>
</form>
<small>Allowed: PDF, TXT, PNG, JPG, JPEG, DOCX. Maximum 10 MB.</small>
</section>

<section class="panel">
<h2>My documents and shared documents</h2>
{% if documents %}
<ul>
{% for doc in documents %}
<li>
<b>{{ doc.original_name }}</b>
— owner: {{ doc.owner.username }}
— <a href="{{ url_for('download', document_id=doc.id) }}">Download</a>

{% if doc.owner_id == current_user.id %}
<form method="post" action="{{ url_for('share', document_id=doc.id) }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Share with username:
<input name="username" required>
</label>
<label><input type="checkbox" name="can_read" checked> Read</label>
<label><input type="checkbox" name="can_edit"> Edit</label>
<button type="submit">Grant access</button>
</form>

<form method="post" action="{{ url_for('revoke', document_id=doc.id) }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Revoke username:
<input name="username" required>
</label>
<button type="submit">Revoke access</button>
</form>
{% endif %}
</li>
{% endfor %}
</ul>
{% else %}
<p>No documents yet. Upload your first document above.</p>
{% endif %}
</section>
{% endif %}
</body>
</html>
"""


AUTH_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ heading }} - TrustVault</title>
</head>
<body>
<h1>{{ heading }}</h1>
{% for message in get_flashed_messages() %}
<p>{{ message }}</p>
{% endfor %}
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label>Username
<input name="username" required minlength="3" maxlength="80">
</label><br>
<label>Password
<input type="password" name="password" required minlength="8">
</label><br>
<button type="submit">{{ heading }}</button>
</form>
<p><a href="{{ url_for('home') }}">Back to TrustVault</a></p>
</body>
</html>
"""


@app.route("/")
def home():
    documents = []

    if current_user.is_authenticated:
        owned = db.session.scalars(
            select(Document).where(
                Document.owner_id == current_user.id
            )
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

        documents = list(
            {doc.id: doc for doc in owned + shared}.values()
        )

    return render_template_string(PAGE, documents=documents)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 80 or len(password) < 8:
            flash("Username must have 3-80 characters and password 8+ characters.")
        elif db.session.scalar(
            select(User).where(User.username == username)
        ):
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
            return redirect(url_for("home"))

    return render_template_string(AUTH_PAGE, heading="Create account")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.session.scalar(
            select(User).where(User.username == username)
        )

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            record_event("login")
            return redirect(url_for("home"))

        record_event(
            "login_failed",
            details=f"Failed login for {username[:80]}",
        )
        flash("Invalid username or password.")

    return render_template_string(AUTH_PAGE, heading="Login")


@app.route("/logout")
@login_required
def logout():
    record_event("logout")
    logout_user()
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
    uploaded.save(destination)

    document = Document(
        original_name=original_name,
        stored_name=stored_name,
        owner_id=current_user.id,
    )
    db.session.add(document)
    db.session.commit()

    record_event("upload", document.id, f"Uploaded {original_name}")
    flash("Document uploaded.")
    return redirect(url_for("home"))


@app.route("/download/<int:document_id>")
@login_required
def download(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_read(document):
        record_event(
            "download_denied",
            document.id,
            "User attempted unauthorized download",
        )
        abort(403)

    file_path = UPLOAD_DIR / document.stored_name

    if not file_path.is_file():
        abort(404)

    record_event("download", document.id, "Document downloaded")

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
        record_event(
            "share_denied",
            document.id,
            "Only the document owner may share access",
        )
        abort(403)

    username = request.form.get("username", "").strip()
    target = db.session.scalar(
        select(User).where(User.username == username)
    )

    if target is None:
        flash("Username not found.")
        return redirect(url_for("home"))

    if target.id == current_user.id:
        flash("You already own this document.")
        return redirect(url_for("home"))

    can_edit_requested = "can_edit" in request.form
    can_read_requested = (
        "can_read" in request.form or can_edit_requested
    )

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == target.id,
        )
    )

    if permission is None:
        permission = Permission(
            document_id=document.id,
            user_id=target.id,
        )
        db.session.add(permission)

    permission.can_read = can_read_requested
    permission.can_edit = can_edit_requested
    db.session.commit()

    record_event(
        "permission_granted",
        document.id,
        f"Access updated for user {target.id}",
    )
    flash("Access permissions updated.")
    return redirect(url_for("home"))


@app.route("/revoke/<int:document_id>", methods=["POST"])
@login_required
def revoke(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        record_event(
            "revoke_denied",
            document.id,
            "Only the owner may revoke access",
        )
        abort(403)

    username = request.form.get("username", "").strip()
    target = db.session.scalar(
        select(User).where(User.username == username)
    )

    if target is None:
        flash("Username not found.")
        return redirect(url_for("home"))

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == target.id,
        )
    )

    if permission is not None:
        db.session.delete(permission)
        db.session.commit()

    record_event(
        "permission_revoked",
        document.id,
        f"Access revoked for user {target.id}",
    )
    flash("Access revoked.")
    return redirect(url_for("home"))


@app.route("/audit")
@login_required
def audit():
    # Users can see their own events and events concerning their documents.
    events = db.session.scalars(
        select(AuditEvent)
        .outerjoin(
            Document,
            AuditEvent.document_id == Document.id,
        )
        .where(
            or_(
                AuditEvent.actor_id == current_user.id,
                Document.owner_id == current_user.id,
            )
        )
        .order_by(AuditEvent.id.desc())
        .limit(200)
    ).all()

    items = "".join(
        "<li>"
        + escape(str(event.created_at))
        + " — "
        + escape(event.action)
        + " — "
        + escape(event.details or "")
        + "</li>"
        for event in events
    )

    return (
        "<h1>Recent audit events</h1><ul>"
        + items
        + '<li><a href="/">Back</a></li></ul>'
    )


@app.before_request
def initialize_database():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
