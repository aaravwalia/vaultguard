"""Practical verification of VaultGuard security controls.

Every test is a test case (TC-xx) in Chapter 5 of the project report and is
linked to the risk (R-xx) whose control it verifies.
Run with:  python -m pytest -v
"""
import io
import os
import sqlite3
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet

from vaultguard import create_app, iso, utcnow
from vaultguard import security as sec

PW = {"admin": "Admin@Vault2026", "auditor": "Audit@Vault2026",
      "alice": "Alice@Vault2026", "bob": "Bob@Vault2026x"}
PDF = b"%PDF-1.7\nVaultGuard confidential test document: SALARY-SHEET-2026\n%%EOF"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTGUARD_MASTER_KEY", Fernet.generate_key().decode())
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "t.db"),
                      "STORAGE": str(tmp_path / "store")})
    os.makedirs(app.config["STORAGE"], exist_ok=True)
    con = sqlite3.connect(app.config["DATABASE"])
    for name, role in [("admin", "admin"), ("auditor", "auditor"), ("alice", "user"), ("bob", "user")]:
        con.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                    (name, sec.hash_password(PW[name]), role, iso(utcnow())))
    con.commit()
    con.close()
    return app


def db(app):
    con = sqlite3.connect(app.config["DATABASE"])
    con.row_factory = sqlite3.Row
    return con


def csrf(client):
    client.get("/login")
    with client.session_transaction() as s:
        return s["csrf"]


def post(client, url, data=None, **kw):
    data = dict(data or {})
    with client.session_transaction() as s:
        data.setdefault("csrf_token", s.get("csrf", ""))
    return client.post(url, data=data, **kw)


def login(client, user, pw=None, ip="10.0.0.5"):
    csrf(client)
    return post(client, "/login", {"username": user, "password": pw or PW[user]},
                environ_base={"REMOTE_ADDR": ip})


def upload(client, name="report.pdf", data=PDF):
    return post(client, "/files/upload", {"file": (io.BytesIO(data), name)},
                content_type="multipart/form-data")


def alerts(app, kind):
    return db(app).execute("SELECT * FROM alerts WHERE kind=?", (kind,)).fetchall()


# ---------------------------------------------------------------- authentication
def test_tc01_weak_password_rejected(app):
    """TC-01 / R1: registration refuses passwords that break the policy."""
    c = app.test_client()
    csrf(c)
    for weak in ["short1!", "alllowercase123!", "NoDigitsHere!!", "Password123", "Password@123", "carolCarol@1"]:
        r = post(c, "/register", {"username": "carol", "password": weak})
        assert r.status_code == 400, weak
    assert db(app).execute("SELECT 1 FROM users WHERE username='carol'").fetchone() is None


def test_tc02_password_stored_as_scrypt_hash(app):
    """TC-02 / R1: no plaintext password is stored."""
    row = db(app).execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
    assert row["password_hash"].startswith("scrypt:")
    assert PW["alice"] not in row["password_hash"]


def test_tc03_no_username_enumeration(app):
    """TC-03 / R1: unknown user and wrong password give the same response."""
    c = app.test_client()
    r1 = login(c, "nobody", "Whatever@123")
    r2 = login(c, "alice", "Wrong@Pass123")
    assert r1.status_code == r2.status_code == 401
    assert b"Invalid username or password." in r1.data and b"Invalid username or password." in r2.data


def test_tc04_account_lockout_after_five_failures(app):
    """TC-04 / R1: 5 failed logins lock the account; even the right password is refused."""
    c = app.test_client()
    for _ in range(5):
        assert login(c, "alice", "Wrong@Pass123").status_code == 401
    assert login(c, "alice").status_code == 401           # correct password, still locked
    assert db(app).execute("SELECT locked_until FROM users WHERE username='alice'").fetchone()[0]
    assert len(alerts(app, "account-lockout")) == 1


def test_tc05_ip_rate_limit(app):
    """TC-05 / R1: more than 20 login attempts from one IP in 10 min returns HTTP 429."""
    c = app.test_client()
    codes = [login(c, f"user{i}", "Wrong@Pass123", ip="203.0.113.9").status_code for i in range(22)]
    assert codes[:20] == [401] * 20 and codes[20:] == [429, 429]
    assert len(alerts(app, "login-rate-limit")) == 1


# ---------------------------------------------------------------- sessions
def test_tc06_logout_invalidates_session_server_side(app):
    """TC-06 / R2: a copied session cookie stops working after logout."""
    c = app.test_client()
    login(c, "alice")
    with c.session_transaction() as s:
        stolen = dict(s)
    post(c, "/logout")
    attacker = app.test_client()
    with attacker.session_transaction() as s:
        s.update(stolen)
    assert attacker.get("/files").status_code == 302


def test_tc07_idle_timeout(app):
    """TC-07 / R2: a session idle for more than 15 minutes is rejected."""
    c = app.test_client()
    login(c, "alice")
    con = db(app)
    con.execute("UPDATE sessions SET last_seen=?", (iso(utcnow() - timedelta(minutes=16)),))
    con.commit()
    r = c.get("/files")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_tc08_admin_can_revoke_sessions(app):
    """TC-08 / R2: admin 'revoke sessions' immediately signs a user out."""
    u, a = app.test_client(), app.test_client()
    login(u, "alice")
    login(a, "admin")
    alice_id = db(app).execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
    post(a, f"/admin/users/{alice_id}/revoke-sessions")
    assert u.get("/files").status_code == 302


def test_tc09_password_change_revokes_other_sessions(app):
    """TC-09 / R2: changing the password signs out other devices."""
    laptop, phone = app.test_client(), app.test_client()
    login(laptop, "alice")
    login(phone, "alice")
    r = post(laptop, "/account/password", {"current": PW["alice"], "new": "New@Secret2026"})
    assert r.status_code == 302
    assert laptop.get("/files").status_code == 200
    assert phone.get("/files").status_code == 302


def test_tc10_disabled_account(app):
    """TC-10 / R3: disabling an account ends its sessions and blocks login."""
    u, a = app.test_client(), app.test_client()
    login(u, "bob")
    login(a, "admin")
    bob_id = db(app).execute("SELECT id FROM users WHERE username='bob'").fetchone()[0]
    post(a, f"/admin/users/{bob_id}/status", {"status": "disabled"})
    assert u.get("/files").status_code == 302
    assert login(app.test_client(), "bob").status_code == 401


# ---------------------------------------------------------------- authorization
def test_tc11_user_cannot_reach_admin_functions(app):
    """TC-11 / R3: a normal user gets 403 on admin pages and actions; probe is logged and alerted."""
    c = app.test_client()
    login(c, "alice")
    assert c.get("/admin/users").status_code == 403
    assert c.get("/audit").status_code == 403
    assert post(c, "/admin/users/2/role", {"role": "admin"}).status_code == 403
    assert db(app).execute("SELECT role FROM users WHERE username='auditor'").fetchone()[0] == "auditor"
    assert len(alerts(app, "privilege-probe")) == 3


def test_tc12_auditor_is_read_only(app):
    """TC-12 / R3: auditor can read and verify the audit log but cannot manage users or resolve alerts."""
    c = app.test_client()
    login(c, "auditor")
    assert c.get("/audit").status_code == 200
    assert post(c, "/audit/verify").status_code == 200
    assert c.get("/admin/users").status_code == 403
    assert post(c, "/alerts/1/resolve").status_code == 403


def test_tc13_admin_cannot_read_user_files(app):
    """TC-13 / R4: separation of duties - administrators have no file permissions."""
    u, a = app.test_client(), app.test_client()
    login(u, "alice")
    upload(u)
    login(a, "admin")
    assert a.get("/files").status_code == 403
    assert a.get("/files/1/download").status_code == 403


def test_tc14_idor_other_users_file(app):
    """TC-14 / R4: Bob cannot download or delete Alice's file by guessing its id (404, not 403)."""
    alice, bob = app.test_client(), app.test_client()
    login(alice, "alice")
    upload(alice)
    login(bob, "bob")
    assert bob.get("/files/1/download").status_code == 404
    assert post(bob, "/files/1/delete").status_code == 404
    assert alice.get("/files/1/download").data == PDF


def test_tc15_role_change_forces_reauthentication(app):
    """TC-15 / R3: changing a user's role revokes that user's sessions."""
    u, a = app.test_client(), app.test_client()
    login(u, "bob")
    login(a, "admin")
    bob_id = db(app).execute("SELECT id FROM users WHERE username='bob'").fetchone()[0]
    post(a, f"/admin/users/{bob_id}/role", {"role": "auditor"})
    assert u.get("/files").status_code == 302


# ---------------------------------------------------------------- files and crypto
def test_tc16_files_encrypted_at_rest(app):
    """TC-16 / R5: the file on disk is ciphertext; plaintext and DEK are not stored."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    row = db(app).execute("SELECT * FROM files").fetchone()
    blob = open(os.path.join(app.config["STORAGE"], row["stored_name"]), "rb").read()
    assert b"SALARY-SHEET-2026" not in blob and not blob.startswith(b"%PDF")
    assert row["stored_name"] != "report.pdf"
    assert c.get("/files/1/download").data == PDF


def test_tc17_upload_validation(app):
    """TC-17 / R6: disallowed types, spoofed content and oversize files are rejected."""
    c = app.test_client()
    login(c, "alice")
    upload(c, "tool.exe", b"MZ\x90\x00 fake executable")
    upload(c, "invoice.pdf", b"MZ\x90\x00 executable renamed to pdf")
    upload(c, "notes.txt", b"\x00\x01\x02binary")
    upload(c, "big.pdf", b"%PDF-" + b"A" * (5 * 1024 * 1024 + 1))
    assert db(app).execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    rejected = db(app).execute("SELECT COUNT(*) FROM audit_log WHERE action='file.upload' AND outcome='rejected'")
    assert rejected.fetchone()[0] == 4


def test_tc18_path_traversal_filename(app):
    """TC-18 / R6: a crafted filename cannot escape the storage directory."""
    c = app.test_client()
    login(c, "alice")
    upload(c, "../../../evil.txt", b"hello")
    row = db(app).execute("SELECT orig_name, stored_name FROM files").fetchone()
    assert row["orig_name"] == "evil.txt" and "/" not in row["stored_name"]


def test_tc19_tampered_file_detected(app):
    """TC-19 / R5: modified ciphertext is refused and raises a high-severity alert."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    row = db(app).execute("SELECT stored_name FROM files").fetchone()
    path = os.path.join(app.config["STORAGE"], row["stored_name"])
    data = bytearray(open(path, "rb").read())
    data[60] ^= 0x01
    open(path, "wb").write(bytes(data))
    assert c.get("/files/1/download").status_code == 500
    assert len(alerts(app, "integrity-failure")) == 1


def test_tc20_delete_crypto_shreds(app):
    """TC-20 / R5: deleting a file removes the blob, discards its key and revokes its shares."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    post(c, "/files/1/share", {"hours": "24", "max_downloads": "3"})
    post(c, "/files/1/delete")
    row = db(app).execute("SELECT * FROM files").fetchone()
    assert row["deleted"] == 1 and row["wrapped_key"] == b""
    assert not os.listdir(app.config["STORAGE"])
    assert db(app).execute("SELECT revoked FROM shares").fetchone()[0] == 1


# ---------------------------------------------------------------- share links
def _share(c, hours="24", max_dl="2"):
    r = post(c, "/files/1/share", {"hours": hours, "max_downloads": max_dl})
    html = r.data.decode()
    return html.split('readonly value="')[1].split('"')[0].replace("http://localhost", "")


def test_tc21_share_link_limits(app):
    """TC-21 / R8: share links enforce download count, expiry and revocation."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    link = _share(c, max_dl="2")
    anon = app.test_client()
    assert anon.get(link).data == PDF
    assert anon.get(link).status_code == 200
    assert anon.get(link).status_code == 404                      # limit reached
    link2 = _share(c)
    con = db(app)
    con.execute("UPDATE shares SET expires_at=? WHERE id=2", (iso(utcnow() - timedelta(seconds=1)),))
    con.commit()
    assert anon.get(link2).status_code == 404                     # expired
    link3 = _share(c)
    post(c, "/shares/3/revoke")
    assert anon.get(link3).status_code == 404                     # revoked
    assert anon.get("/s/guessed-token-value").status_code == 404


def test_tc22_share_token_stored_hashed(app):
    """TC-22 / R8: only a SHA-256 digest of the share token is stored."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    token = _share(c).rsplit("/", 1)[1]
    stored = db(app).execute("SELECT token_hash FROM shares").fetchone()[0]
    assert stored != token and stored == sec.token_digest(token)
    assert len(token) >= 40          # 32 random bytes, URL-safe


# ---------------------------------------------------------------- web protections
def test_tc23_csrf_required(app):
    """TC-23 / R9: state-changing requests without a valid CSRF token are refused."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    r = c.post("/files/1/delete", data={"csrf_token": "forged"})
    assert r.status_code == 400
    assert db(app).execute("SELECT deleted FROM files").fetchone()[0] == 0


def test_tc24_security_headers(app):
    """TC-24 / R9: responses carry CSP, anti-framing and no-sniff headers; cookie is HttpOnly."""
    c = app.test_client()
    r = login(c, "alice")
    h = r.headers
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert "HttpOnly" in h["Set-Cookie"] and "SameSite=Lax" in h["Set-Cookie"]


# ---------------------------------------------------------------- audit and monitoring
def test_tc25_audit_records_are_attributable(app):
    """TC-25 / R10: audit entries record actor, action, target, outcome, IP and time."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    row = db(app).execute("SELECT * FROM audit_log WHERE action='file.upload'").fetchone()
    assert row["actor"] == "alice" and row["outcome"] == "success" and row["target"] == "file:1"
    assert row["ip"] == "127.0.0.1" and row["ts"].endswith("Z")
    login_row = db(app).execute("SELECT * FROM audit_log WHERE action='auth.login'").fetchone()
    assert login_row["ip"] == "10.0.0.5"


def test_tc26_audit_log_append_only(app):
    """TC-26 / R10: the database refuses UPDATE and DELETE on audit records."""
    login(app.test_client(), "alice")
    con = db(app)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        con.execute("UPDATE audit_log SET outcome='success' WHERE id=1")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        con.execute("DELETE FROM audit_log")


def test_tc27_hash_chain_detects_tampering(app):
    """TC-27 / R10: an attacker who bypasses the triggers is still detected by the hash chain."""
    c = app.test_client()
    login(c, "alice", "Wrong@Pass123")
    login(c, "alice")
    with app.app_context():
        assert app.verify_chain()[0] is True
    con = db(app)
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("UPDATE audit_log SET outcome='success' WHERE id=1")   # hide the failed login
    con.commit()
    with app.app_context():
        ok, bad_id, _ = app.verify_chain()
    assert ok is False and bad_id == 1
    a = app.test_client()
    login(a, "auditor")
    r = post(a, "/audit/verify")
    assert b"Hash chain BROKEN at record #1" in r.data
    assert len(alerts(app, "audit-tamper")) == 1


def test_tc28_download_burst_alert(app):
    """TC-28 / R11: 10 downloads within 60 s raises a possible data-exfiltration alert."""
    c = app.test_client()
    login(c, "alice")
    upload(c)
    for _ in range(10):
        c.get("/files/1/download")
    assert len(alerts(app, "download-burst")) == 1
