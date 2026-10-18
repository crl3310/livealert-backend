"""Shared security helpers: authentication, authorisation, validation, rate limiting."""
import functools
import logging
import math
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import timezone

import requests
from firebase_admin import auth as fb_auth
from flask import g, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app_core import get_db

log = logging.getLogger(__name__)


def env_flag(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------
# Config / constants
# --------------------------------------------------------------------------
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
CHECK_REVOKED = env_flag("CHECK_REVOKED_TOKENS", False)          # extra network call per request
REQUIRE_SESSION_HEADER = env_flag("REQUIRE_SESSION_HEADER", False)  # enforce X-Session-Id on every call

RESPONDER_ROLES = {"responder", "responder_admin", "super_admin", "commander", "admin"}
GLOBAL_ADMIN_ROLES = {"super_admin", "admin"}
TERMINAL_STATUSES = {"resolved", "cancelled", "cancelled_fake", "fake", "rejected"}

CHANNEL_RE = re.compile(r"^(?!\.)(?!__)[A-Za-z0-9_\-:.@+=]{1,64}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
EMAIL_RE = re.compile(r"^[^@\s/]{1,64}@[^@\s/]+\.[^@\s/]+$")

# IP-based limiter for the unauthenticated endpoints (login, register, verification).
# Behind a proxy/load balancer set TRUSTED_PROXY_COUNT or every client shares one IP.
limiter = Limiter(get_remote_address, storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"))


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def error(message, status, **extra):
    body = {"success": False, "message": message}
    body.update(extra)
    return jsonify(body), status


def normalize_email(value):
    return str(value or "").strip().lower()


def valid_email(email):
    return bool(email) and len(email) <= 254 and bool(EMAIL_RE.match(email))


def clean_str(value, max_len):
    if value is None:
        return ""
    return str(value).strip()[:max_len]


def valid_channel(name):
    return isinstance(name, str) and bool(CHANNEL_RE.match(name))


def parse_coords(lat, lon):
    """Returns (lat, lon) floats or raises ValueError if missing/out of range/NaN."""
    lat_f, lon_f = float(lat), float(lon)
    if not (-90.0 <= lat_f <= 90.0 and -180.0 <= lon_f <= 180.0):
        raise ValueError("coordinates out of range")
    return lat_f, lon_f


def as_aware_utc(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Firebase email/password sign-in (REST), shared by every login/re-auth path
# --------------------------------------------------------------------------
def firebase_sign_in(email, password):
    """Returns (data, None) on success or (None, (message, http_status)) on failure.
    Firebase's raw error codes (EMAIL_NOT_FOUND, INVALID_PASSWORD, ...) are collapsed so the
    API doesn't reveal which emails have accounts."""
    api_key = os.getenv("FIREBASE_WEB_API_KEY")
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    try:
        res = requests.post(
            url,
            json={"email": email, "password": password, "returnSecureToken": True},
            timeout=10,
        )
    except requests.RequestException:
        log.exception("Firebase sign-in request failed")
        return None, ("Authentication service unavailable. Please try again.", 503)

    try:
        body = res.json()
    except ValueError:
        body = {}

    if res.status_code == 200:
        return body, None

    code = (body.get("error") or {}).get("message", "")
    if code.startswith("TOO_MANY_ATTEMPTS"):
        return None, ("Too many attempts. Please try again later.", 429)
    if code == "USER_DISABLED":
        return None, ("This account has been disabled.", 403)
    return None, ("Invalid email or password.", 401)


# --------------------------------------------------------------------------
# Authentication: Firebase ID token in "Authorization: Bearer <token>"
# --------------------------------------------------------------------------
def _bearer_token():
    header = request.headers.get("Authorization", "")
    if header[:7].lower() == "bearer ":
        return header[7:].strip() or None
    return None


def get_profile():
    """(collection_name, profile_dict) for the signed-in uid. Cached per request.
    Looks in Responders first, then Users, exactly like the original login flow."""
    if not hasattr(g, "_profile"):
        db = get_db()
        doc = db.collection("Responders").document(g.uid).get()
        if doc.exists:
            g._profile = ("Responders", doc.to_dict() or {})
        else:
            doc = db.collection("Users").document(g.uid).get()
            g._profile = ("Users", doc.to_dict() or {}) if doc.exists else (None, {})
    return g._profile


def profile_role():
    return str(get_profile()[1].get("role") or "").strip().lower()


def is_responder():
    coll, profile = get_profile()
    if coll == "Responders":
        return True
    return coll == "Users" and profile_role() in RESPONDER_ROLES


def require_auth(fn=None, *, responder=False):
    """Use as @require_auth or @require_auth(responder=True).
    Sets g.uid / g.claims. The caller's identity ALWAYS comes from the verified token,
    never from a uid/uuid sent in the request body."""

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            token = _bearer_token()
            if not token:
                return error("Authentication required.", 401)
            try:
                claims = fb_auth.verify_id_token(token, check_revoked=CHECK_REVOKED, clock_skew_seconds=10)
            except fb_auth.ExpiredIdTokenError:
                return error("Session expired. Please sign in again.", 401, code="TOKEN_EXPIRED")
            except fb_auth.RevokedIdTokenError:
                return error("Session revoked. Please sign in again.", 401, code="TOKEN_REVOKED")
            except fb_auth.UserDisabledError:
                return error("This account has been disabled.", 403)
            except fb_auth.CertificateFetchError:
                return error("Authentication service unavailable. Please try again.", 503)
            except (fb_auth.InvalidIdTokenError, ValueError):
                return error("Invalid authentication token.", 401)
            except Exception:
                log.exception("Unexpected token verification failure")
                return error("Invalid authentication token.", 401)

            g.uid = claims["uid"]
            g.claims = claims

            # Single-device enforcement: the app sends the sessionId it got at login.
            session_id = request.headers.get("X-Session-Id")
            if session_id or REQUIRE_SESSION_HEADER:
                stored = get_profile()[1].get("sessionId")
                if not session_id or not stored or session_id != stored:
                    return error("This account was signed in on another device.", 401, code="SESSION_REPLACED")

            if responder and not is_responder():
                return error("Responder access required.", 403)
            return view(*args, **kwargs)

        return wrapper

    return decorator(fn) if fn else decorator


# --------------------------------------------------------------------------
# Per-user rate limiting (for authenticated endpoints; in-memory, single process)
# --------------------------------------------------------------------------
_hits = defaultdict(deque)
_hits_lock = threading.Lock()


def user_rate_limit(name, max_calls, per_seconds):
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            key, now = (name, g.uid), time.monotonic()
            with _hits_lock:
                if len(_hits) > 20000:  # opportunistic cleanup of idle keys
                    for k in [k for k, q in _hits.items() if not q or now - q[-1] > 3600]:
                        _hits.pop(k, None)
                q = _hits[key]
                while q and now - q[0] > per_seconds:
                    q.popleft()
                if len(q) >= max_calls:
                    retry = int(per_seconds - (now - q[0])) + 1
                    resp = error("Too many requests. Please slow down.", 429, retryAfter=retry)
                    resp[0].headers["Retry-After"] = str(retry)
                    return resp
                q.append(now)
            return view(*args, **kwargs)

        return wrapper

    return decorator


# --------------------------------------------------------------------------
# Authorisation helpers for emergency calls
# --------------------------------------------------------------------------
def call_unit_ids(call):
    station = call.get("assignedStation") or {}
    ids = call.get("unitIds") or station.get("unitIds") or []
    if isinstance(ids, str):
        ids = [ids]
    ids = list(ids)
    single = call.get("unitId") or station.get("unitId")
    if single and single not in ids:
        ids.append(single)
    return ids


def _norm_id(value):
    return str(value or "").strip().upper()


def responder_can_access_call(call):
    """A responder may touch a call if they're a global admin, work at the call's station,
    or their unit is assigned to it."""
    _, profile = get_profile()
    if profile_role() in GLOBAL_ADMIN_ROLES:
        return True
    station = call.get("assignedStation") or {}
    call_station = _norm_id(station.get("stationId") or call.get("stationId"))
    my_station = _norm_id(profile.get("stationId"))
    if call_station and my_station and call_station == my_station:
        return True
    my_unit = profile.get("unitId") or g.uid
    return my_unit in call_unit_ids(call)


def caller_can_view_call(call):
    """Reporter of the call, or a responder with access to it."""
    if call.get("reporterUuid") == g.uid:
        return True
    return is_responder() and responder_can_access_call(call)
