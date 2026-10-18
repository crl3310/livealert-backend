import logging
import uuid

from firebase_admin import messaging
from flask import jsonify, request

from app_core import get_db
from app_security import error, firebase_sign_in, limiter, normalize_email
from .register import auth_bp

log = logging.getLogger(__name__)


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute; 100 per hour")
def login():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    password = data.get('password')
    fcm_token = data.get('fcmToken')  # Incoming device FCM token

    if not email or not isinstance(password, str) or not password:
        return error("Missing credentials", 400)
    if fcm_token is not None and (not isinstance(fcm_token, str) or len(fcm_token) > 4096):
        return error("Invalid fcmToken.", 400)

    try:
        db = get_db()

        # 1. Verify the password first, so we never reveal whether an email is registered/verified.
        res_data, fail = firebase_sign_in(email, password)
        if fail:
            return error(fail[0], fail[1])

        uid = res_data.get('localId')
        id_token = res_data.get('idToken')
        refresh_token = res_data.get('refreshToken')

        user_ref = db.collection('Users').document(uid)
        user_doc = user_ref.get()
        user_profile = user_doc.to_dict() if user_doc.exists else {}

        # 2. Email must be verified. Profile flag first; legacy VerificationCodes doc as fallback.
        verified = bool(user_profile.get('isVerified'))
        if not verified:
            legacy = db.collection('VerificationCodes').document(email).get()
            verified = legacy.exists and bool((legacy.to_dict() or {}).get('verified'))
        if not verified:
            return error("Email address not verified. Please verify your 6-digit code first.", 403,
                         requiresVerification=True)

        # 3. Single-device session enforcement
        old_fcm_token = user_profile.get('fcmToken')
        new_session_id = str(uuid.uuid4())

        if old_fcm_token and fcm_token and old_fcm_token != fcm_token:
            try:
                messaging.send(messaging.Message(
                    token=old_fcm_token,
                    data={"type": "FORCE_LOGOUT", "message": "Your account was logged in from another device."},
                ))
                log.info("Sent FORCE_LOGOUT push to previous device for user %s", uid)
            except Exception:
                log.exception("Failed to send force logout notification")

        # Always rotate the session id (previously only saved when an FCM token was sent).
        session_update = {'sessionId': new_session_id}
        if fcm_token:
            session_update['fcmToken'] = fcm_token
        user_ref.set(session_update, merge=True)

        # 4. Profile for the app
        user_profile.update(session_update)
        bd = user_profile.get('birthdate')
        if bd is not None and hasattr(bd, 'strftime'):
            user_profile['birthdate'] = bd.strftime('%Y-%m-%d')

        return jsonify({
            "success": True,
            "message": "Login successful!",
            "uid": uid,
            "token": id_token,
            "refreshToken": refresh_token,   # NEW: lets the app renew the 1-hour ID token
            "sessionId": new_session_id,
            "profile": user_profile
        }), 200

    except Exception:
        log.exception("Login failed")
        return error("Login failed. Please try again.", 500)
