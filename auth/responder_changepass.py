import logging
import os
import re

import requests
from flask import g, jsonify, request

from app_core import get_db
from app_security import (MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, error, firebase_sign_in, get_profile,
                          limiter, require_auth)
from .register import auth_bp

log = logging.getLogger(__name__)

# Keep this identical to BADGE_RE in your responder login file.
BADGE_RE = re.compile(r'^[A-Z0-9][A-Z0-9\-]{2,19}$')


def normalize_badge(value):
    """Trim + uppercase. Returns '' if the value isn't a valid badge number."""
    if not isinstance(value, str):
        return ''
    badge = value.strip().upper()
    return badge if BADGE_RE.match(badge) else ''


def _load_profile(coll):
    """Reads the signed-in user's profile document. Returns {} if it can't be found."""
    if not coll:
        return {}
    try:
        snap = get_db().collection(coll).document(g.uid).get()
        return (snap.to_dict() or {}) if snap.exists else {}
    except Exception:
        log.exception("Could not load profile for uid %s", g.uid)
        return {}


@auth_bp.route('/responder/change-password', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
@require_auth
def change_password():
    """
    Requires a valid login token. The account is taken from the token.
    The app sends the badge number (not the email); it is only used as a
    sanity check against the signed-in account.
    """
    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    # Email comes from the token and is used only to talk to Firebase.
    email = (g.claims.get('email') or '').lower()
    if not email:
        return error("Signed-in account has no email.", 401)

    if not isinstance(old_password, str) or not isinstance(new_password, str) \
            or not old_password or not new_password:
        return error("Missing old password or new password.", 400)

    if not (MIN_PASSWORD_LEN <= len(new_password) <= MAX_PASSWORD_LEN):
        return error(f"New password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long.", 400)

    try:
        # Find which collection holds this profile (Responders or Users)
        coll, _ = get_profile()

        # Badge sent by the app (if any) must belong to the signed-in account
        raw_badge = data.get('badge') or data.get('badgeNumber') or data.get('username')
        if raw_badge:
            profile = _load_profile(coll)
            account_badge = normalize_badge(profile.get('badge') or profile.get('badgeNumber'))
            if not account_badge or normalize_badge(raw_badge) != account_badge:
                return error("Badge number does not match the signed-in account.", 403)

        # 1. Re-authenticate with the current password
        auth_data, fail = firebase_sign_in(email, old_password)
        if fail:
            status = fail[1] if fail[1] in (429, 503) else 401
            msg = "Invalid current password." if status == 401 else fail[0]
            return error(msg, status)

        # 2. Update password via Firebase Auth REST API
        api_key = os.getenv("FIREBASE_WEB_API_KEY")
        update_res = requests.post(
            f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}",
            json={"idToken": auth_data.get('idToken'), "password": new_password, "returnSecureToken": True},
            timeout=10,
        )
        if update_res.status_code != 200:
            log.error("Firebase password update failed: %s", update_res.text[:300])
            return error("Failed to update password.", 500)
        new_tokens = update_res.json()

        # 3. is_new -> False in whichever collection holds this profile
        if coll:
            get_db().collection(coll).document(g.uid).set({"is_new": False}, merge=True)

        return jsonify({
            "success": True,
            "message": "Password updated successfully. is_new status set to false.",
            # Old refresh tokens are invalidated by a password change; hand the app fresh ones.
            "token": new_tokens.get('idToken'),
            "refreshToken": new_tokens.get('refreshToken'),
        }), 200

    except Exception:
        log.exception("Change password failed")
        return error("Change password failed. Please try again.", 500)