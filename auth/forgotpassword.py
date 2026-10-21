"""Forgot password (user is NOT logged in).

  1. POST /api/auth/forgot-password/send-otp    {email}
  2. POST /api/auth/forgot-password/verify-otp  {email, code}              -> {resetToken}
  3. POST /api/auth/forgot-password/reset       {email, resetToken, new_password}
"""
import logging

from firebase_admin import auth
from flask import jsonify, request

from app_core import get_db
from app_security import (MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, error, limiter, normalize_email,
                          valid_email)
from .verify import (consume_reset_token, issue_password_otp, password_otp_failure,
                     verify_password_otp)
from .register import auth_bp

log = logging.getLogger(__name__)

GENERIC_SENT = "If an account exists for this email, a verification code has been sent."


def _invalidate_sessions(uid):
    """Kill every active session so the old device(s) must log in with the new password."""
    db = get_db()
    for coll in ("Responders", "Users"):
        ref = db.collection(coll).document(uid)
        snap = ref.get()
        if snap.exists:
            update = {"sessionId": None}
            if (snap.to_dict() or {}).get("is_new"):
                update["is_new"] = False       # they chose their own password now
            ref.update(update)


@auth_bp.route('/forgot-password/send-otp', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
def forgot_send_otp():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    if not email:
        return error("Email is required.", 400)
    if not valid_email(email):
        return error("Please enter a valid email address.", 400)

    # Same response whether or not the account exists, so this can't be used to find registered emails.
    try:
        try:
            user = auth.get_user_by_email(email)
        except auth.UserNotFoundError:
            return jsonify({"success": True, "message": GENERIC_SENT}), 200
        if user.disabled:
            return jsonify({"success": True, "message": GENERIC_SENT}), 200

        issue_password_otp("reset", email, user.uid, "Your LiveAlert Password Reset Code")
    except Exception:
        log.exception("forgot-password send-otp failed")
    return jsonify({"success": True, "message": GENERIC_SENT}), 200


@auth_bp.route('/forgot-password/verify-otp', methods=['POST'])
@limiter.limit("10 per minute; 60 per hour")
def forgot_verify_otp():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    code = str(data.get('code') or '').strip()
    if not email or not code:
        return error("Email and code are required.", 400)

    try:
        result, token = verify_password_otp("reset", email, code, mode="issue_token")
    except Exception:
        log.exception("forgot-password verify-otp failed")
        return error("Verification failed. Please try again.", 500)

    if result != "ok":
        return password_otp_failure(result)
    return jsonify({"success": True, "message": "Code verified.", "resetToken": token}), 200


@auth_bp.route('/forgot-password/reset', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
def forgot_reset():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    reset_token = data.get('resetToken')
    new_password = data.get('new_password')

    if not email or not isinstance(reset_token, str) or not reset_token \
            or not isinstance(new_password, str) or not new_password:
        return error("Email, resetToken and new_password are required.", 400)
    if not (MIN_PASSWORD_LEN <= len(new_password) <= MAX_PASSWORD_LEN):
        return error(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long.", 400)

    try:
        uid = consume_reset_token(email, reset_token)
        if not uid:
            return error("Reset session is invalid or expired. Please start over.", 400)

        auth.update_user(uid, password=new_password)
        auth.revoke_refresh_tokens(uid)
        _invalidate_sessions(uid)

        return jsonify({"success": True,
                        "message": "Password reset successfully. Please log in with your new password."}), 200
    except ValueError:
        return error("Invalid password format.", 400)
    except Exception:
        log.exception("forgot-password reset failed")
        return error("Could not reset the password. Please try again.", 500)