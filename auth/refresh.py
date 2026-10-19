import hmac
import logging
import os

import requests
from flask import jsonify, request

from app_core import get_db
from app_security import error, limiter
from .register import auth_bp

log = logging.getLogger(__name__)

SECURETOKEN_URL = "https://securetoken.googleapis.com/v1/token"


@auth_bp.route('/refresh', methods=['POST'])
@limiter.limit("30 per minute; 300 per hour")
def refresh():
    """
    Exchange a refresh token for a new ID token, but ONLY if the caller's sessionId
    is still the current one for that account (single-device enforcement).

    Body: { "refreshToken": "...", "sessionId": "..." }
    On a stale session the response is 401 with sessionInvalid=True: the app should log out.
    """
    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refreshToken')
    session_id = data.get('sessionId')

    if not isinstance(refresh_token, str) or not refresh_token \
            or not isinstance(session_id, str) or not session_id:
        return error("refreshToken and sessionId are required.", 400)

    try:
        # 1. Ask Firebase to exchange the refresh token
        api_key = os.getenv("FIREBASE_WEB_API_KEY")
        res = requests.post(
            f"{SECURETOKEN_URL}?key={api_key}",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            timeout=10,
        )
        if res.status_code != 200:
            # Expired/revoked token, disabled or deleted user, etc.
            log.info("Token refresh rejected: %s", res.text[:200])
            return error("Session expired. Please log in again.", 401, sessionInvalid=True)
        tokens = res.json()

        uid = tokens.get('user_id')
        if not uid:
            return error("Session expired. Please log in again.", 401, sessionInvalid=True)

        # 2. Find the profile (same lookup order as responder_login: Responders, then Users)
        db = get_db()
        doc = db.collection('Responders').document(uid).get()
        if not doc.exists:
            doc = db.collection('Users').document(uid).get()
        profile = doc.to_dict() if doc.exists else None
        if not profile:
            return error("Account not found.", 401, sessionInvalid=True)

        # 3. Compare sessionId. A missing stored value counts as invalid (forces a fresh login).
        stored = str(profile.get('sessionId') or '')
        if not stored or not hmac.compare_digest(stored, session_id):
            return error("You were logged in from another device.", 401, sessionInvalid=True)

        # 4. Hand back the new tokens. Firebase may rotate the refresh token, so always return it.
        return jsonify({
            "success": True,
            "uid": uid,
            "token": tokens.get('id_token'),
            "refreshToken": tokens.get('refresh_token') or refresh_token,
            "expiresIn": tokens.get('expires_in'),
        }), 200

    except requests.RequestException:
        log.exception("Token refresh could not reach Firebase")
        return error("Could not refresh the session. Please try again.", 503)
    except Exception:
        log.exception("Token refresh failed")
        return error("Could not refresh the session. Please try again.", 500)