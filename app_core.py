"""Firebase initialisation + small shared helpers.

Replaces the old `import server; server.db` pattern. That pattern re-imported
server.py (and re-ran all of its start-up code) when the app was started with
`python server.py`, and it can't work cleanly under gunicorn.
"""
import json
import logging
import os
from datetime import timedelta

import firebase_admin
from firebase_admin import credentials, firestore, storage

log = logging.getLogger(__name__)

STORAGE_BUCKET = os.getenv("FIREBASE_STORAGE_BUCKET", "livealert-d12cc.firebasestorage.app")
_db = None


def _load_credentials():
    """Prefer env-provided credentials (containers / secret managers); fall back to a file."""
    raw_json = os.getenv("FIREBASE_CREDENTIALS_JSON")
    if raw_json:
        return credentials.Certificate(json.loads(raw_json))
    path = os.getenv("FIREBASE_CREDENTIALS_PATH", "firebase-credentials.json")
    if os.path.exists(path):
        return credentials.Certificate(path)
    return credentials.ApplicationDefault()


def init_firebase():
    """Initialise Firebase once and return the Firestore client. Raises on failure (fail fast)."""
    global _db
    if _db is None:
        if not firebase_admin._apps:
            firebase_admin.initialize_app(_load_credentials(), {"storageBucket": STORAGE_BUCKET})
            log.info("Firebase Admin SDK initialised")
        _db = firestore.client()
    return _db


def get_db():
    return _db if _db is not None else init_firebase()


def get_bucket():
    return storage.bucket(STORAGE_BUCKET)


def signed_url(path, expires=timedelta(hours=1)):
    """Temporary read link for a private Storage object. Returns None on failure."""
    if not path:
        return None
    try:
        return get_bucket().blob(path).generate_signed_url(
            version="v4", expiration=expires, method="GET"
        )
    except Exception:
        log.exception("Could not sign URL for %s", path)
        return None
