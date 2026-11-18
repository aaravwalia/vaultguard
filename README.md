# VaultGuard – Secure File Vault with Risk-Driven Security Controls

Course project for **21CSC308T – Security Risk Management Principles**.

VaultGuard is a Flask + SQLite file vault. Every security control in it treats a risk from the
project's risk register (see `report/VaultGuard_Project_Report.docx`), and 28 automated attack
tests (`tests/test_security.py`) verify that the controls work.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
flask --app vaultguard seed      # demo accounts (passwords in vaultguard/seed.py)
flask --app vaultguard run       # http://127.0.0.1:5000
python -m pytest -v              # 28 security tests
```

Demo accounts: `admin`, `auditor`, `alice`, `bob`. They are for local demonstration only.

## Security controls → risks

| Risk | Control | Tests |
|---|---|---|
| R1 credential attacks | password policy, scrypt, lockout (5 fails / 15 min), IP rate limit, generic errors | TC-01–05 |
| R2 session replay | server-side sessions, 15 min idle / 8 h absolute timeout, revocation | TC-06–09 |
| R3 privilege escalation | server-side RBAC, re-auth on role change, disable ends sessions | TC-10–12, 15 |
| R4 unauthorised file access | ownership checks (404), admins have no file permission | TC-13–14 |
| R5 storage compromise | envelope encryption (per-file key), SHA-256 integrity, crypto-shredding | TC-16, 19, 20 |
| R6 malicious upload | allow-list, magic bytes, size limit, filename sanitising | TC-17–18 |
| R8 share-link abuse | expiry, download limit, revocation, hashed tokens | TC-21–22 |
| R9 CSRF / clickjacking | CSRF tokens, CSP, X-Frame-Options, cookie flags | TC-23–24 |
| R10 audit tampering | append-only triggers + SHA-256 hash chain verification | TC-25–27 |
| R11 exfiltration | download-burst alert | TC-28 |

Known residual risks (R7 master key on host, R12 no backups, no MFA) are documented in Chapter 5 of the report.

## Layout

```
vaultguard/          application (security.py, db.py, __init__.py, templates/, static/)
tests/               security test suite
report/              report generator (build_report.js), screenshots, diagrams, .docx and .pdf
sample_files/        demo documents used for screenshots
```
