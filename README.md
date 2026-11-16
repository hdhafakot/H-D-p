# H&D Productions — private staff system (development)

This is the original v6 prototype source, prepared for a **private GitHub repository**. It is **not production ready** and must not be deployed as a public web service with real users or identity documents.

## Included
- `app.py` FastAPI application
- `static/index.html` Hebrew mobile-friendly UI
- `requirements.txt` dependencies
- `.gitignore` prevents accidental commits of common secret/data files
- `.env.example` placeholders only (never real secrets)

## Local development
Requires Python 3.11+ and packages from `requirements.txt`.
Set `HD_ADMIN_PHONE`, `HD_ADMIN_PASSWORD`, and `HD_DATA_KEY` securely in the environment. Generate a Fernet key using `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
Run `uvicorn app:app --host 127.0.0.1 --port 8000` for local testing.

## Before Render deployment
- Security review and tests (CSRF, MFA, durable rate limiting, access controls, audit logs, uploaded file validation, privacy/retention policy)
- Persistent database storage and tested encrypted backups; default SQLite path on ephemeral hosting is unsafe for production
- HTTPS, secure environment secrets, secure administrator onboarding
- QR is not yet per-guest; camera scanning is not implemented
- Validate all business logic and printable vouchers
- Never commit a real `.env`, database, identity document, or encryption key

**Upload only these source files to a PRIVATE GitHub repository. Do not deploy publicly yet.**
