import logging
import re
import secrets
import uuid

from firebase_admin import auth as fb_auth
from firebase_admin import messaging
from flask import jsonify, request
from flask_limiter.util import get_remote_address
from google.cloud.firestore import GeoPoint
from google.cloud.firestore_v1.base_query import FieldFilter

from app_core import get_db
from app_security import RESPONDER_ROLES, error, firebase_sign_in, limiter
from .register import auth_bp

log = logging.getLogger(__name__)

# Adjust to match your real badge format.
BADGE_RE = re.compile(r'^[A-Z0-9][A-Z0-9\-]{2,19}$')

# One message for every credential failure, so the response never reveals
# whether a badge number exists.
GENERIC_AUTH_ERROR = "Invalid badge number or password."


def normalize_badge(value):
    """Trim + uppercase. Returns '' if the value isn't a valid badge number."""
    if not isinstance(value, str):
        return ''
    badge = value.strip().upper()
    return badge if BADGE_RE.match(badge) else ''


def _badge_key():
    """Rate-limit bucket per badge, so one account can't be brute-forced from many IPs."""
    data = request.get_json(silent=True) or {}
    badge = normalize_badge(data.get('badgeNumber') or data.get('username'))
    return f"badge:{badge}" if badge else get_remote_address()


def find_responder_by_badge(db, badge):
    """
    Returns (doc_ref, profile_dict) or (None, None).
    Looks in 'Responders' first, then 'Users' (responder roles only).
    Refuses to continue if a badge matches more than one account.
    """
    matches = []

    for snap in db.collection('Responders').where(
            filter=FieldFilter('badge', '==', badge)).limit(2).stream():
        matches.append((snap.reference, snap.to_dict() or {}))

    # Always check Users too (responder roles only), so a badge that exists in
    # both collections is caught as a duplicate instead of silently picking one.
    for snap in db.collection('Users').where(
            filter=FieldFilter('badgeNumber', '==', badge)).limit(2).stream():
        data = snap.to_dict() or {}
        if str(data.get('role', '')).lower() in RESPONDER_ROLES:
            matches.append((snap.reference, data))

    if len(matches) > 1:
        log.error("Duplicate badge number detected: %s", badge)
        return None, None
    return matches[0] if matches else (None, None)


def get_login_email(doc_ref, profile):
    """Email is only used server-side to talk to Firebase; it is never taken from the request."""
    email = str(profile.get('email') or '').strip().lower()
    if email:
        return email
    try:
        return (fb_auth.get_user(doc_ref.id).email or '').lower()
    except Exception:
        log.exception("Could not resolve email for uid %s", doc_ref.id)
        return ''


def serialize_doc(data):
    """Recursively converts Firestore GeoPoint objects into standard JSON dicts."""
    if not isinstance(data, dict):
        return data

    cleaned = {}
    for key, value in data.items():
        if isinstance(value, GeoPoint):
            cleaned[key] = {"latitude": value.latitude, "longitude": value.longitude}
        elif isinstance(value, dict):
            cleaned[key] = serialize_doc(value)
        elif isinstance(value, list):
            cleaned[key] = [serialize_doc(item) if isinstance(item, dict) else item for item in value]
        else:
            cleaned[key] = value
    return cleaned


def _fail_response(fail):
    """Pass through throttling/outage errors, flatten everything else to the generic message."""
    status = fail[1]
    if status in (429, 503):
        return error(fail[0], status)
    return error(GENERIC_AUTH_ERROR, 401)


@auth_bp.route('/responder/login', methods=['POST'])
@limiter.limit("10 per minute; 100 per hour")
@limiter.limit("5 per minute; 30 per hour", key_func=_badge_key)
def responder_login():
    data = request.get_json(silent=True) or {}

    raw_badge = data.get('badgeNumber') or data.get('username')
    password = data.get('password')
    fcm_token = data.get('fcmToken')  # optional
    duty_status = data.get('duty')    # optional duty status override

    badge = normalize_badge(raw_badge)
    if not badge or not isinstance(password, str) or not password:
        return error("Missing or invalid badge number or password.", 400)
    if fcm_token is not None and (not isinstance(fcm_token, str) or len(fcm_token) > 4096):
        return error("Invalid fcmToken.", 400)

    try:
        db = get_db()

        # 1. Resolve badge number -> account (server-side only)
        profile_ref, responder_profile = find_responder_by_badge(db, badge)
        email = get_login_email(profile_ref, responder_profile) if profile_ref else ''

        if not profile_ref or not email:
            # Burn a comparable Firebase round-trip so unknown badges can't be
            # detected by response time, then return the same error as a bad password.
            firebase_sign_in(f"{secrets.token_hex(8)}@invalid.example", secrets.token_urlsafe(12))
            return error(GENERIC_AUTH_ERROR, 401)

        # 2. Authenticate credentials via Firebase Auth REST API
        res_data, fail = firebase_sign_in(email, password)
        if fail:
            return _fail_response(fail)

        uid = res_data.get('localId')
        id_token = res_data.get('idToken')
        refresh_token = res_data.get('refreshToken')

        # Defense in depth: the authenticated Firebase account must be the one
        # that owns this badge number.
        if uid != profile_ref.id:
            log.error("Badge %s resolved to %s but Firebase authenticated %s", badge, profile_ref.id, uid)
            return error(GENERIC_AUTH_ERROR, 401)

        # --- SINGLE-DEVICE SESSION ENFORCEMENT FOR RESPONDERS ---
        old_fcm_token = responder_profile.get('fcmToken')
        new_session_id = str(uuid.uuid4())

        if old_fcm_token and fcm_token and old_fcm_token != fcm_token:
            try:
                messaging.send(messaging.Message(
                    token=old_fcm_token,
                    data={"type": "FORCE_LOGOUT",
                          "message": "Your responder account was logged in from another device."},
                ))
                log.info("Sent FORCE_LOGOUT push to previous device for responder %s", uid)
            except Exception:
                log.exception("Failed to send responder force logout notification")

        # 3. Register/Update FCM Token, Session ID, and Duty Status in Firestore
        update_data = {"sessionId": new_session_id}
        responder_profile["sessionId"] = new_session_id

        if fcm_token:
            update_data["fcmToken"] = fcm_token
            responder_profile["fcmToken"] = fcm_token

        if duty_status:
            val = str(duty_status).lower()
            update_data["duty"] = "on_duty" if val in ['on', 'on_duty', 'online', 'true'] else "off_duty"
            responder_profile["duty"] = update_data["duty"]
        elif "duty" not in responder_profile:
            update_data["duty"] = "on_duty"
            responder_profile["duty"] = "on_duty"

        profile_ref.set(update_data, merge=True)

        # 4. Retrieve assigned Station information
        station_info = None
        station_id = responder_profile.get('stationId')
        if station_id:
            station_doc = db.collection('Stations').document(str(station_id)).get()
            if station_doc.exists:
                station_info = station_doc.to_dict()
                station_info['id'] = station_doc.id

        # 5. Retrieve assigned Unit information
        unit_info = None
        unit_id = responder_profile.get('unitId') or uid
        if unit_id:
            unit_doc = db.collection('Units').document(str(unit_id)).get()
            if unit_doc.exists:
                unit_info = unit_doc.to_dict()
                unit_info['id'] = unit_doc.id

        clean_profile = serialize_doc(responder_profile)

        return jsonify({
            "success": True,
            "message": "Responder authenticated successfully.",
            "uid": uid,
            "badgeNumber": badge,
            "token": id_token,
            "refreshToken": refresh_token,
            "sessionId": new_session_id,
            "role": clean_profile.get('role', 'responder'),
            "is_new": clean_profile.get('is_new', False),
            "profile": clean_profile,
            "station": serialize_doc(station_info),
            "unit": serialize_doc(unit_info)
        }), 200

    except Exception:
        log.exception("Responder login failed")
        return error("Responder login failed. Please try again.", 500)