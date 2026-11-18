"""VaultGuard - Secure File Vault with Risk-Driven Security Controls.

21CSC308T Security Risk Management Principles - course project.
"""
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from io import BytesIO

from . import security as sec
from .db import close_db, get_db, init_db

# ---------------------------------------------------------------------------
# Role-based access control: role -> permissions.
# Admins manage accounts but deliberately have NO file permissions
# (separation of duties: an administrator cannot read users' files).
# ---------------------------------------------------------------------------
PERMISSIONS = {
    "user": {"file.upload", "file.read_own", "file.share"},
    "admin": {"user.manage", "session.revoke", "audit.read", "audit.verify",
              "alert.read", "alert.resolve"},
    "auditor": {"audit.read", "audit.verify", "alert.read"},
}

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
IDLE_TIMEOUT_MIN = 15
ABSOLUTE_TIMEOUT_HOURS = 8
IP_LOGIN_LIMIT = 20            # login attempts per IP ...
IP_LOGIN_WINDOW_SEC = 600      # ... per 10 minutes
DOWNLOAD_BURST = 10            # downloads by one user ...
DOWNLOAD_BURST_SEC = 60        # ... within 60 seconds raises an alert


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        SECRET_KEY=os.environ.get("VAULTGUARD_SECRET_KEY") or _instance_secret(app.instance_path),
        DATABASE=os.path.join(app.instance_path, "vaultguard.db"),
        STORAGE=os.path.join(app.instance_path, "storage"),
        MAX_UPLOAD_BYTES=5 * 1024 * 1024,
        MAX_CONTENT_LENGTH=6 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("VAULTGUARD_HTTPS") == "1",
        SESSION_COOKIE_NAME="vg_session",
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.config["STORAGE"], exist_ok=True)
    init_db(app.config["DATABASE"])
    master_key, key_source = sec.load_master_key(app.instance_path)
    app.config["KEY_SOURCE"] = key_source
    keys = sec.KeyManager(master_key)
    ip_attempts: dict[str, deque] = defaultdict(deque)

    app.teardown_appcontext(close_db)

    # ------------------------------------------------------------------
    # Audit and alert helpers
    # ------------------------------------------------------------------
    def client_ip() -> str:
        return request.remote_addr or "unknown"

    def audit(action: str, target: str, outcome: str, detail: str = "", actor: str | None = None):
        db = get_db()
        if actor is None:
            actor = g.user["username"] if g.get("user") else "anonymous"
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else sec.GENESIS
        ts = iso(utcnow())
        ip = client_ip()
        h = sec.audit_hash(prev, ts, actor, action, target, outcome, ip, detail)
        db.execute(
            "INSERT INTO audit_log (ts, actor, action, target, outcome, ip, detail, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, actor, action, target, outcome, ip, detail, prev, h),
        )
        db.commit()

    def alert(severity: str, kind: str, detail: str):
        db = get_db()
        db.execute("INSERT INTO alerts (ts, severity, kind, detail) VALUES (?,?,?,?)",
                   (iso(utcnow()), severity, kind, detail))
        db.commit()

    def verify_chain() -> tuple[bool, int | None, int]:
        rows = get_db().execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        prev = sec.GENESIS
        for r in rows:
            expected = sec.audit_hash(prev, r["ts"], r["actor"], r["action"], r["target"],
                                      r["outcome"], r["ip"], r["detail"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return False, r["id"], len(rows)
            prev = r["hash"]
        return True, None, len(rows)

    app.audit, app.alert, app.verify_chain = audit, alert, verify_chain

    # ------------------------------------------------------------------
    # Session handling (server-side session table)
    # ------------------------------------------------------------------
    def start_session(user):
        session.clear()                        # prevents session fixation
        sid = sec.new_token()
        now = iso(utcnow())
        db = get_db()
        db.execute("INSERT INTO sessions (id_hash, user_id, created_at, last_seen, ip) VALUES (?,?,?,?,?)",
                   (sec.token_digest(sid), user["id"], now, now, client_ip()))
        db.commit()
        session["sid"] = sid
        session["csrf"] = sec.new_token(24)

    def end_session():
        sid = session.get("sid")
        if sid:
            db = get_db()
            db.execute("UPDATE sessions SET revoked = 1 WHERE id_hash = ?", (sec.token_digest(sid),))
            db.commit()
        session.clear()

    @app.before_request
    def load_user():
        g.user = None
        sid = session.get("sid")
        if not sid:
            return
        db = get_db()
        row = db.execute(
            "SELECT s.*, u.username, u.role, u.status FROM sessions s JOIN users u ON u.id = s.user_id"
            " WHERE s.id_hash = ?", (sec.token_digest(sid),)).fetchone()
        now = utcnow()
        reason = None
        if row is None:
            reason = "unknown session"
        elif row["revoked"]:
            reason = "revoked session"
        elif row["status"] != "active":
            reason = "account disabled"
        elif now - parse(row["last_seen"]) > timedelta(minutes=IDLE_TIMEOUT_MIN):
            reason = "idle timeout"
        elif now - parse(row["created_at"]) > timedelta(hours=ABSOLUTE_TIMEOUT_HOURS):
            reason = "absolute timeout"
        if reason:
            if row is not None and not row["revoked"]:
                db.execute("UPDATE sessions SET revoked = 1 WHERE id_hash = ?", (row["id_hash"],))
                db.commit()
            session.clear()
            g.session_end_reason = reason
            return
        db.execute("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", (iso(now), row["id_hash"]))
        db.commit()
        g.user = {"id": row["user_id"], "username": row["username"], "role": row["role"]}

    @app.before_request
    def csrf_protect():
        if request.method == "POST" and not request.path.startswith("/s/"):
            sent = request.form.get("csrf_token", "")
            if not session.get("csrf") or not sec.tokens_equal(sent, session["csrf"]):
                # Pre-login forms get a CSRF token too (see csrf_token()).
                audit("csrf.reject", request.path, "denied")
                abort(400, "Invalid or missing CSRF token.")

    @app.context_processor
    def inject():
        def csrf_token():
            if "csrf" not in session:
                session["csrf"] = sec.new_token(24)
            return session["csrf"]

        def can(perm):
            return bool(g.get("user")) and perm in PERMISSIONS[g.user["role"]]
        return {"csrf_token": csrf_token, "can": can, "current_user": g.get("user")}

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------------
    # Authorization decorators
    # ------------------------------------------------------------------
    def login_required(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if g.user is None:
                if g.get("session_end_reason"):
                    flash(f"Session ended ({g.session_end_reason}). Please sign in again.", "warn")
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapped

    def permission_required(perm):
        def deco(view):
            @wraps(view)
            @login_required
            def wrapped(*a, **kw):
                if perm not in PERMISSIONS[g.user["role"]]:
                    audit("authz.deny", f"{request.method} {request.path}", "denied", f"needs {perm}")
                    alert("medium", "privilege-probe",
                          f"{g.user['username']} ({g.user['role']}) requested {request.path} without {perm}")
                    abort(403)
                return view(*a, **kw)
            return wrapped
        return deco

    # ------------------------------------------------------------------
    # Authentication routes
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        if g.user is None:
            return redirect(url_for("login"))
        return redirect(url_for("dashboard"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            errors = []
            if not (3 <= len(username) <= 30) or not username.replace("_", "").isalnum():
                errors.append("Username must be 3-30 letters, digits or underscores.")
            problems = sec.password_problems(password, username)
            if problems:
                errors.append("Password needs: " + ", ".join(problems) + ".")
            db = get_db()
            if not errors and db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                errors.append("That username is not available.")
            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template("register.html", username=username), 400
            db.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                       (username, sec.hash_password(password), "user", iso(utcnow())))
            db.commit()
            audit("user.register", username, "success", actor=username)
            flash("Account created. Please sign in.", "ok")
            return redirect(url_for("login"))
        return render_template("register.html", username="")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = client_ip()
            now_t = time.time()
            q = ip_attempts[ip]
            while q and now_t - q[0] > IP_LOGIN_WINDOW_SEC:
                q.popleft()
            if len(q) >= IP_LOGIN_LIMIT:
                audit("auth.login", "-", "rate-limited", f"ip {ip}", actor="anonymous")
                if len(q) == IP_LOGIN_LIMIT:
                    alert("high", "login-rate-limit", f"IP {ip} exceeded {IP_LOGIN_LIMIT} login attempts in 10 min")
                q.append(now_t)
                return render_template("login.html", error="Too many attempts. Try again later."), 429
            q.append(now_t)

            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            generic = "Invalid username or password."
            if user is None:
                sec.verify_password(sec.DUMMY_HASH, password)     # equalise timing
                audit("auth.login", username or "-", "failure", "unknown user", actor="anonymous")
                return render_template("login.html", error=generic), 401
            if user["locked_until"] and parse(user["locked_until"]) > utcnow():
                audit("auth.login", username, "locked", "attempt during lockout", actor="anonymous")
                return render_template("login.html", error=generic), 401
            if user["status"] != "active" or not sec.verify_password(user["password_hash"], password):
                fails = user["failed_attempts"] + 1
                locked_until = None
                if fails >= MAX_FAILED_LOGINS:
                    locked_until = iso(utcnow() + timedelta(minutes=LOCKOUT_MINUTES))
                    fails = 0
                    alert("high", "account-lockout",
                          f"{username} locked for {LOCKOUT_MINUTES} min after {MAX_FAILED_LOGINS} failed logins from {ip}")
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                           (fails, locked_until, user["id"]))
                db.commit()
                audit("auth.login", username, "failure",
                      "disabled account" if user["status"] != "active" else "bad password", actor="anonymous")
                return render_template("login.html", error=generic), 401
            db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
            db.commit()
            start_session(user)
            audit("auth.login", username, "success", actor=username)
            return redirect(url_for("dashboard"))
        return render_template("login.html", error=None)

    @app.route("/logout", methods=["POST"])
    def logout():
        if g.user:
            audit("auth.logout", g.user["username"], "success")
        end_session()
        flash("Signed out.", "ok")
        return redirect(url_for("login"))

    @app.route("/account/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
            current = request.form.get("current", "")
            new = request.form.get("new", "")
            if not sec.verify_password(user["password_hash"], current):
                audit("account.password", g.user["username"], "failure", "wrong current password")
                flash("Current password is incorrect.", "error")
                return render_template("password.html"), 400
            problems = sec.password_problems(new, user["username"])
            if problems:
                flash("Password needs: " + ", ".join(problems) + ".", "error")
                return render_template("password.html"), 400
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (sec.hash_password(new), user["id"]))
            # Changing the password ends every other session of this user.
            db.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id_hash != ?",
                       (user["id"], sec.token_digest(session["sid"])))
            db.commit()
            audit("account.password", g.user["username"], "success", "other sessions revoked")
            flash("Password changed. Other sessions were signed out.", "ok")
            return redirect(url_for("dashboard"))
        return render_template("password.html")

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        db = get_db()
        stats = {}
        if g.user["role"] == "user":
            stats["files"] = db.execute("SELECT COUNT(*) c FROM files WHERE owner_id=? AND deleted=0",
                                        (g.user["id"],)).fetchone()["c"]
            stats["shares"] = db.execute(
                "SELECT COUNT(*) c FROM shares s JOIN files f ON f.id=s.file_id WHERE f.owner_id=? AND s.revoked=0"
                " AND s.expires_at > ? AND s.downloads < s.max_downloads",
                (g.user["id"], iso(utcnow()))).fetchone()["c"]
        else:
            stats["users"] = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
            stats["open_alerts"] = db.execute("SELECT COUNT(*) c FROM alerts WHERE resolved=0").fetchone()["c"]
            stats["events_24h"] = db.execute("SELECT COUNT(*) c FROM audit_log WHERE ts > ?",
                                             (iso(utcnow() - timedelta(hours=24)),)).fetchone()["c"]
            stats["failed_24h"] = db.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE action='auth.login' AND outcome!='success' AND ts > ?",
                (iso(utcnow() - timedelta(hours=24)),)).fetchone()["c"]
        recent = db.execute("SELECT * FROM audit_log WHERE actor=? ORDER BY id DESC LIMIT 8",
                            (g.user["username"],)).fetchall()
        return render_template("dashboard.html", stats=stats, recent=recent,
                               key_source=app.config["KEY_SOURCE"])

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------
    def own_file_or_404(file_id: int):
        """Object-level authorization: returns 404 (not 403) so that the
        existence of other users' files is not revealed (prevents IDOR)."""
        f = get_db().execute("SELECT * FROM files WHERE id = ? AND deleted = 0", (file_id,)).fetchone()
        if f is None or f["owner_id"] != g.user["id"]:
            audit("file.access", f"file:{file_id}", "denied", "not owner or missing")
            abort(404)
        return f

    def read_and_check(f) -> bytes:
        path = os.path.join(app.config["STORAGE"], f["stored_name"])
        with open(path, "rb") as fh:
            blob = fh.read()
        try:
            data = keys.decrypt(keys.unwrap(f["wrapped_key"]), blob)
        except sec.InvalidToken:
            alert("high", "integrity-failure", f"file:{f['id']} failed decryption/authentication")
            audit("file.integrity", f"file:{f['id']}", "failure", "ciphertext rejected")
            abort(500, "File failed integrity verification.")
        if sec.sha256_hex(data) != f["sha256"]:
            alert("high", "integrity-failure", f"file:{f['id']} SHA-256 mismatch")
            audit("file.integrity", f"file:{f['id']}", "failure", "hash mismatch")
            abort(500, "File failed integrity verification.")
        return data

    def check_download_burst(actor: str):
        since = iso(utcnow() - timedelta(seconds=DOWNLOAD_BURST_SEC))
        n = get_db().execute(
            "SELECT COUNT(*) c FROM audit_log WHERE actor=? AND action IN ('file.download','share.download')"
            " AND outcome='success' AND ts >= ?", (actor, since)).fetchone()["c"]
        if n == DOWNLOAD_BURST:
            alert("medium", "download-burst", f"{actor} downloaded {n} files within {DOWNLOAD_BURST_SEC}s")

    @app.route("/files")
    @permission_required("file.read_own")
    def files():
        rows = get_db().execute("SELECT * FROM files WHERE owner_id=? AND deleted=0 ORDER BY id DESC",
                                (g.user["id"],)).fetchall()
        return render_template("files.html", files=rows, allowed=", ".join(sorted(sec.ALLOWED_TYPES)))

    @app.route("/files/upload", methods=["POST"])
    @permission_required("file.upload")
    def upload():
        up = request.files.get("file")
        if up is None or not up.filename:
            flash("Choose a file to upload.", "error")
            return redirect(url_for("files"))
        name = sec.clean_filename(up.filename)
        data = up.read()
        problem = sec.validate_upload(name, data, app.config["MAX_UPLOAD_BYTES"])
        if problem:
            audit("file.upload", name, "rejected", problem)
            flash(problem, "error")
            return redirect(url_for("files"))
        dek, wrapped = keys.new_wrapped_key()
        stored = sec.new_token(18)
        with open(os.path.join(app.config["STORAGE"], stored), "wb") as fh:
            fh.write(keys.encrypt(dek, data))
        db = get_db()
        cur = db.execute(
            "INSERT INTO files (owner_id, orig_name, stored_name, size, sha256, wrapped_key, uploaded_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (g.user["id"], name, stored, len(data), sec.sha256_hex(data), wrapped, iso(utcnow())))
        db.commit()
        audit("file.upload", f"file:{cur.lastrowid}", "success", f"{name} ({len(data)} bytes)")
        flash(f"Uploaded and encrypted {name}.", "ok")
        return redirect(url_for("files"))

    @app.route("/files/<int:file_id>/download")
    @permission_required("file.read_own")
    def download(file_id):
        f = own_file_or_404(file_id)
        data = read_and_check(f)
        audit("file.download", f"file:{file_id}", "success", f["orig_name"])
        check_download_burst(g.user["username"])
        return send_file(BytesIO(data), as_attachment=True, download_name=f["orig_name"],
                         mimetype="application/octet-stream")

    @app.route("/files/<int:file_id>/delete", methods=["POST"])
    @permission_required("file.upload")
    def delete_file(file_id):
        f = own_file_or_404(file_id)
        path = os.path.join(app.config["STORAGE"], f["stored_name"])
        if os.path.exists(path):
            os.remove(path)
        db = get_db()
        # Crypto-shredding: discard the wrapped key so any backup copy of the
        # ciphertext can no longer be decrypted.
        db.execute("UPDATE files SET deleted=1, wrapped_key=X'' WHERE id=?", (file_id,))
        db.execute("UPDATE shares SET revoked=1 WHERE file_id=?", (file_id,))
        db.commit()
        audit("file.delete", f"file:{file_id}", "success", f["orig_name"])
        flash(f"Deleted {f['orig_name']}.", "ok")
        return redirect(url_for("files"))

    # ------------------------------------------------------------------
    # Share links
    # ------------------------------------------------------------------
    @app.route("/files/<int:file_id>/share", methods=["POST"])
    @permission_required("file.share")
    def create_share(file_id):
        f = own_file_or_404(file_id)
        try:
            hours = int(request.form.get("hours", "24"))
            max_dl = int(request.form.get("max_downloads", "3"))
        except ValueError:
            abort(400)
        hours = max(1, min(hours, 168))
        max_dl = max(1, min(max_dl, 20))
        token = sec.new_token()
        db = get_db()
        db.execute(
            "INSERT INTO shares (file_id, token_hash, created_by, created_at, expires_at, max_downloads)"
            " VALUES (?,?,?,?,?,?)",
            (file_id, sec.token_digest(token), g.user["id"], iso(utcnow()),
             iso(utcnow() + timedelta(hours=hours)), max_dl))
        db.commit()
        audit("share.create", f"file:{file_id}", "success", f"{hours}h, {max_dl} downloads")
        link = url_for("shared_download", token=token, _external=True)
        return render_template("share_created.html", link=link, f=f, hours=hours, max_dl=max_dl)

    @app.route("/shares")
    @permission_required("file.share")
    def shares():
        rows = get_db().execute(
            "SELECT s.*, f.orig_name FROM shares s JOIN files f ON f.id=s.file_id"
            " WHERE f.owner_id=? ORDER BY s.id DESC", (g.user["id"],)).fetchall()
        return render_template("shares.html", shares=rows, now=iso(utcnow()))

    @app.route("/shares/<int:share_id>/revoke", methods=["POST"])
    @permission_required("file.share")
    def revoke_share(share_id):
        db = get_db()
        s = db.execute("SELECT s.* FROM shares s JOIN files f ON f.id=s.file_id WHERE s.id=? AND f.owner_id=?",
                       (share_id, g.user["id"])).fetchone()
        if s is None:
            abort(404)
        db.execute("UPDATE shares SET revoked=1 WHERE id=?", (share_id,))
        db.commit()
        audit("share.revoke", f"share:{share_id}", "success")
        flash("Share link revoked.", "ok")
        return redirect(url_for("shares"))

    @app.route("/s/<token>")
    def shared_download(token):
        db = get_db()
        s = db.execute("SELECT * FROM shares WHERE token_hash=?", (sec.token_digest(token),)).fetchone()
        reason = None
        if s is None:
            reason = "unknown token"
        elif s["revoked"]:
            reason = "revoked"
        elif parse(s["expires_at"]) <= utcnow():
            reason = "expired"
        elif s["downloads"] >= s["max_downloads"]:
            reason = "download limit reached"
        if reason:
            audit("share.download", f"share:{s['id']}" if s else "share:?", "denied", reason, actor="anonymous")
            return render_template("share_denied.html"), 404
        f = db.execute("SELECT * FROM files WHERE id=? AND deleted=0", (s["file_id"],)).fetchone()
        if f is None:
            return render_template("share_denied.html"), 404
        data = read_and_check(f)
        db.execute("UPDATE shares SET downloads = downloads + 1 WHERE id=?", (s["id"],))
        db.commit()
        audit("share.download", f"share:{s['id']}", "success", f["orig_name"], actor="anonymous")
        return send_file(BytesIO(data), as_attachment=True, download_name=f["orig_name"],
                         mimetype="application/octet-stream")

    # ------------------------------------------------------------------
    # Administration
    # ------------------------------------------------------------------
    @app.route("/admin/users")
    @permission_required("user.manage")
    def admin_users():
        db = get_db()
        rows = db.execute(
            "SELECT u.*, (SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.id AND s.revoked=0) AS live_sessions"
            " FROM users u ORDER BY u.id").fetchall()
        return render_template("admin_users.html", users=rows, now=iso(utcnow()))

    def target_user(user_id):
        u = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if u is None:
            abort(404)
        if u["id"] == g.user["id"]:
            flash("You cannot change your own account from the admin panel.", "error")
            return None
        return u

    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @permission_required("user.manage")
    def admin_set_role(user_id):
        u = target_user(user_id)
        role = request.form.get("role")
        if u and role in PERMISSIONS:
            db = get_db()
            db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
            # A change of privilege forces re-authentication.
            db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))
            db.commit()
            audit("admin.role", u["username"], "success", f"{u['role']} -> {role}")
            alert("low", "privilege-change", f"{g.user['username']} changed {u['username']}: {u['role']} -> {role}")
            flash(f"{u['username']} is now {role}.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/status", methods=["POST"])
    @permission_required("user.manage")
    def admin_set_status(user_id):
        u = target_user(user_id)
        status = request.form.get("status")
        if u and status in ("active", "disabled"):
            db = get_db()
            db.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))
            if status == "disabled":
                db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))
            db.commit()
            audit("admin.status", u["username"], "success", f"{u['status']} -> {status}")
            flash(f"{u['username']} is now {status}.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
    @permission_required("user.manage")
    def admin_unlock(user_id):
        u = target_user(user_id)
        if u:
            db = get_db()
            db.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?", (user_id,))
            db.commit()
            audit("admin.unlock", u["username"], "success")
            flash(f"{u['username']} unlocked.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/revoke-sessions", methods=["POST"])
    @permission_required("session.revoke")
    def admin_revoke_sessions(user_id):
        u = target_user(user_id)
        if u:
            db = get_db()
            n = db.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0", (user_id,)).rowcount
            db.commit()
            audit("admin.revoke_sessions", u["username"], "success", f"{n} sessions")
            flash(f"Revoked {n} session(s) for {u['username']}.", "ok")
        return redirect(url_for("admin_users"))

    # ------------------------------------------------------------------
    # Audit log and alerts
    # ------------------------------------------------------------------
    @app.route("/audit")
    @permission_required("audit.read")
    def audit_view():
        q = request.args.get("q", "").strip()
        db = get_db()
        if q:
            like = f"%{q}%"
            rows = db.execute(
                "SELECT * FROM audit_log WHERE actor LIKE ? OR action LIKE ? OR target LIKE ? OR outcome LIKE ?"
                " ORDER BY id DESC LIMIT 300", (like, like, like, like)).fetchall()
        else:
            rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300").fetchall()
        return render_template("audit.html", rows=rows, q=q, chain=None)

    @app.route("/audit/verify", methods=["POST"])
    @permission_required("audit.verify")
    def audit_verify():
        ok, bad_id, total = verify_chain()
        if not ok:
            alert("high", "audit-tamper", f"Audit hash chain broken at record {bad_id}")
        audit("audit.verify", "audit_log", "success" if ok else "failure",
              f"{total} records" + ("" if ok else f", broken at {bad_id}"))
        rows = get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300").fetchall()
        return render_template("audit.html", rows=rows, q="", chain={"ok": ok, "bad_id": bad_id, "total": total})

    @app.route("/alerts")
    @permission_required("alert.read")
    def alerts_view():
        rows = get_db().execute("SELECT * FROM alerts ORDER BY resolved, id DESC LIMIT 200").fetchall()
        return render_template("alerts.html", rows=rows)

    @app.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
    @permission_required("alert.resolve")
    def resolve_alert(alert_id):
        db = get_db()
        db.execute("UPDATE alerts SET resolved=1, resolved_by=? WHERE id=?", (g.user["username"], alert_id))
        db.commit()
        audit("alert.resolve", f"alert:{alert_id}", "success")
        return redirect(url_for("alerts_view"))

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, message="You do not have permission for this action."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="Not found."), 404

    @app.errorhandler(413)
    def too_large(_e):
        return render_template("error.html", code=413, message="Upload too large."), 413

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, message=getattr(e, "description", "Bad request.")), 400

    from .seed import register_cli
    register_cli(app)
    return app


def _instance_secret(instance_path: str) -> str:
    path = os.path.join(instance_path, "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(os.urandom(32).hex())
    with open(path) as fh:
        return fh.read().strip()
