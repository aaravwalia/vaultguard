"""`flask --app vaultguard seed` creates demo accounts for the project demo.

DEMO CREDENTIALS - for local demonstration only, never for a real deployment.
    admin    / Admin2026   (role: admin)
    auditor  / Audit@Vault2026   (role: auditor)
    alice    / Alice@Vault2026   (role: user)
    bob      / Bob@Vault2026    (role: user)
"""
import click

DEMO_USERS = [
    ("admin", "Admin", "admin"),
    ("auditor", "Audit", "auditor"),
    ("alice", "Alice", "user"),
    ("bob", "Bob", "user"),
]


def register_cli(app):
    @app.cli.command("seed")
    def seed():
        """Create the demo accounts listed in vaultguard/seed.py."""
        from . import iso, utcnow
        from . import security as sec
        from .db import get_db
        db = get_db()
        for username, password, role in DEMO_USERS:
            if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                click.echo(f"exists: {username}")
                continue
            db.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                       (username, sec.hash_password(password), role, iso(utcnow())))
            click.echo(f"created: {username} ({role})")
        db.commit()
        with app.test_request_context():
            app.audit("system.seed", "users", "success", "demo accounts", actor="system")
