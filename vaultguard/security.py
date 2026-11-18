"""Security primitives for VaultGuard.

Contains password policy, password hashing, envelope encryption for files,
file-type validation, token helpers and the tamper-evident audit hash chain.
"""
import hashlib
import hmac
import os
import re
import secrets

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Password policy and hashing
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "password123", "123456789", "qwerty123", "letmein123",
    "welcome123", "admin12345", "iloveyou12", "srmist2026", "abcdefghij",
    "password@123", "welcome@123", "admin@12345",
}


def password_problems(password: str, username: str = "") -> list[str]:
    """Return a list of policy violations (empty list means the password is OK)."""
    problems = []
    if len(password) < 10:
        problems.append("at least 10 characters")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a special character")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("not a commonly used password")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    return problems


def hash_password(password: str) -> str:
    # scrypt is memory-hard, which slows down offline guessing of stolen hashes.
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


# A fixed dummy hash so that logins for unknown users take the same time as
# logins for real users (reduces username enumeration through timing).
DUMMY_HASH = generate_password_hash("not-a-real-password!A1", method="scrypt")


# ---------------------------------------------------------------------------
# Envelope encryption
# ---------------------------------------------------------------------------
class KeyManager:
    """Each file gets its own data key (DEK). The DEK is encrypted ("wrapped")
    with the master key (KEK). Only the wrapped DEK is stored in the database."""

    def __init__(self, master_key: bytes):
        self._kek = Fernet(master_key)

    def new_wrapped_key(self) -> tuple[bytes, bytes]:
        dek = Fernet.generate_key()
        return dek, self._kek.encrypt(dek)

    def unwrap(self, wrapped: bytes) -> bytes:
        return self._kek.decrypt(wrapped)

    @staticmethod
    def encrypt(dek: bytes, data: bytes) -> bytes:
        return Fernet(dek).encrypt(data)

    @staticmethod
    def decrypt(dek: bytes, blob: bytes) -> bytes:
        return Fernet(dek).decrypt(blob)


def load_master_key(instance_path: str) -> tuple[bytes, str]:
    """Load the master key from the environment, or fall back to a key file.

    Returns (key, source). The key-file fallback is a known residual risk that
    the report records: the key then sits on the same host as the data.
    """
    env_key = os.environ.get("VAULTGUARD_MASTER_KEY")
    if env_key:
        return env_key.encode(), "environment"
    path = os.path.join(instance_path, "master.key")
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(Fernet.generate_key())
    with open(path, "rb") as fh:
        return fh.read().strip(), "key-file"


__all__ = ["InvalidToken"]

# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------
# extension -> accepted leading "magic" bytes (None = plain text, checked separately)
ALLOWED_TYPES = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "txt": None,
    "csv": None,
}


def clean_filename(name: str) -> str:
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return name[:120] or "file"


def validate_upload(filename: str, data: bytes, max_bytes: int) -> str | None:
    """Return an error message, or None if the upload is acceptable."""
    if not data:
        return "Empty file."
    if len(data) > max_bytes:
        return f"File exceeds the {max_bytes // (1024 * 1024)} MB limit."
    if "." not in filename:
        return "File has no extension."
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_TYPES:
        return f"File type .{ext} is not allowed."
    signatures = ALLOWED_TYPES[ext]
    if signatures is None:
        if b"\x00" in data:
            return "Text file contains binary content."
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return "Text file contains binary content."
    elif not any(data.startswith(sig) for sig in signatures):
        return f"File content does not match the .{ext} extension."
    return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    """Share links and session ids are stored only as SHA-256 digests."""
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")


# ---------------------------------------------------------------------------
# Audit hash chain
# ---------------------------------------------------------------------------
GENESIS = "0" * 64


def audit_hash(prev_hash: str, ts: str, actor: str, action: str, target: str,
               outcome: str, ip: str, detail: str) -> str:
    material = "|".join([prev_hash, ts, actor, action, target, outcome, ip, detail])
    return hashlib.sha256(material.encode()).hexdigest()
