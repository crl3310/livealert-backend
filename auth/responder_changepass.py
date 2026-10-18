import logging
import os

import requests
from flask import g, jsonify, request

from app_core import get_db
from app_security import (MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, error, firebase_sign_in, get_profile,
                          limiter, require_auth)
from .register import auth_bp

log = logging.getLogger(__name__)


@auth_bp.route('/responder/change-password', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
@require_auth
def change_password():
    """Requires a valid login token. The account is taken from the token, not from the body."""
    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    email = (g.claims.get('email') or '').lower()
    body_email = str(data.get('email') or '').strip().lower()
    if body_email and body_email != email:
        return error("Email does not match the signed-in account.", 403)

    if not email or not isinstance(old_password, str) or not isinstance(new_password, str) \
            or not old_password or not new_password:
        return error("Missing old password or new password.", 400)

    if not (MIN_PASSWORD_LEN <= len(new_password) <= MAX_PASSWORD_LEN):
        return error(f"New password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long.", 400)

    try:
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
        coll, _ = get_profile()
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
