"""Change password (user IS logged in). Works for both normal users and responders.

  1. POST /api/auth/change-password/send-otp   (Bearer token)  -> emails a code to the account's email
  2. POST /api/auth/change-password            (Bearer token)  {old_password, new_password, code}
"""
import logging

from firebase_admin import auth
from flask import g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from app_core import get_db
from app_security import (MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, error, firebase_sign_in, get_profile,
                          limiter, require_auth)
from .register import auth_bp
from .verify import issue_password_otp, password_otp_failure, verify_password_otp

log = logging.getLogger(_name_)


def _account_email():
    return (g.claims.get('email') or '').strip().lower()


@auth_bp.route('/change-password/send-otp', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
@require_auth
def change_password_send_otp():
    email = _account_email()
    if not email:
        return error("This account has no email address.", 400)
    try:
        sent = issue_password_otp("change", email, g.uid, "Your LiveAlert Change Password Code")
    except Exception:
        log.exception("change-password send-otp failed")
        return error("Could not send the verification email. Please try again.", 500)
    if not sent:
        return error("Please wait a minute before requesting another code.", 429)
    return jsonify({"success": True, "message": "Verification code sent to your email."}), 200


@auth_bp.route('/change-password', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
@require_auth
def change_password_confirm():
    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    code = str(data.get('code') or '').strip()
    email = _account_email()

    if not email or not isinstance(old_password, str) or not isinstance(new_password, str) \
            or not old_password or not new_password or not code:
        return error("old_password, new_password and code are required.", 400)
    if not (MIN_PASSWORD_LEN <= len(new_password) <= MAX_PASSWORD_LEN):
        return error(f"New password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long.", 400)
    if new_password == old_password:
        return error("New password must be different from the current password.", 400)

    try:
        # 1. Current password first, so a typo here doesn't burn the OTP.
        _, fail = firebase_sign_in(email, old_password)
        if fail:
            status = fail[1] if fail[1] in (429, 503) else 401
            return error("Invalid current password." if status == 401 else fail[0], status)

        # 2. Check password history to prevent reusing recent passwords[cite: 2]
        coll, profile = get_profile()
        password_history = profile.get('password_history', []) if profile else []
        for old_hash in password_history:
            if check_password_hash(old_hash, new_password):
                return error("New password cannot be one of your recent passwords.", 400)

        # 3. OTP (single use, bound to this uid)[cite: 2]
        result, _ = verify_password_otp("change", email, code, mode="consume", expected_uid=g.uid)
        if result != "ok":
            return password_otp_failure(result)

        # 4. Update the password[cite: 2]
        auth.update_user(g.uid, password=new_password)

        # 5. Update password history (store old password hash) and profile flags
        new_history_entry = generate_password_hash(old_password)
        updated_history = [new_history_entry] + [h for h in password_history if not check_password_hash(h, new_password)]
        updated_history = updated_history[:3]  # Keep last 3 passwords

        if coll:
            get_db().collection(coll).document(g.uid).set({
                "is_new": False,
                "password_history": updated_history
            }, merge=True)

        # 6. A password change invalidates old refresh tokens: sign in again so THIS device stays logged in.[cite: 2]
        tokens, fail = firebase_sign_in(email, new_password)
        resp = {"success": True, "message": "Password updated successfully."}
        if not fail:
            resp["token"] = tokens.get('idToken')
            resp["refreshToken"] = tokens.get('refreshToken')
        return jsonify(resp), 200

    except ValueError:
        return error("Invalid password format.", 400)
    except Exception:
        log.exception("Change password failed")
        return error("Change password failed. Please try again.", 500)