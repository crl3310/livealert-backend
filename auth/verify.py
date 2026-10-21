import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import jsonify, request
from flask_mailman import EmailMessage
from google.cloud import firestore as gcf

from app_core import get_db
from app_security import as_aware_utc, error, limiter, normalize_email, valid_email
from .register import auth_bp

log = logging.getLogger(__name__)

CODE_TTL = timedelta(minutes=15)
RESEND_COOLDOWN = timedelta(seconds=60)
MAX_ATTEMPTS = 5


# ==========================================================================
# 1) REGISTRATION email verification  (unchanged)
# ==========================================================================
@auth_bp.route('/send-verification', methods=['POST'])
@limiter.limit("5 per minute; 30 per hour")
def send_verification():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))

    if not email:
        return error("Email is required.", 400)
    if not valid_email(email):
        return error("Please enter a valid email address.", 400)

    now = datetime.now(timezone.utc)
    try:
        ref = get_db().collection('VerificationCodes').document(email)

        # Per-email cooldown: stops someone mail-bombing a victim through our SMTP account.
        existing = ref.get()
        if existing.exists:
            created = (existing.to_dict() or {}).get('created_at')
            if created and now - as_aware_utc(created) < RESEND_COOLDOWN:
                return error("Please wait a minute before requesting another code.", 429)

        code = f"{secrets.randbelow(900000) + 100000}"  # cryptographically secure
        ref.set({
            'code': code,
            'expires_at': now + CODE_TTL,
            'created_at': now,
            'attempts': 0,
            'verified': False,
        })

        msg = EmailMessage(
            subject="Your LiveAlert Verification Code",
            body=f"Your 6-digit verification code is: {code}\n\nThis code will expire in 15 minutes.",
            to=[email],
        )
        msg.send()
        return jsonify({"success": True, "message": "Verification code sent to your email!"}), 200

    except Exception:
        log.exception("send-verification failed")
        return error("Could not send the verification email. Please try again.", 500)


@gcf.transactional
def _check_code(transaction, ref, submitted, now):
    snap = ref.get(transaction=transaction)
    if not snap.exists:
        return "missing"
    d = snap.to_dict() or {}
    if d.get('verified'):
        return "used"
    expires = d.get('expires_at')
    if expires is None or now > as_aware_utc(expires):
        return "expired"
    attempts = int(d.get('attempts', 0))
    if attempts >= MAX_ATTEMPTS:
        return "locked"
    if hmac.compare_digest(str(d.get('code', '')), submitted):
        transaction.update(ref, {'verified': True, 'verified_at': now})
        return "ok"
    transaction.update(ref, {'attempts': attempts + 1})
    return "invalid"


@auth_bp.route('/verify-code', methods=['POST'])
@limiter.limit("10 per minute; 60 per hour")
def verify_code():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    user_code = str(data.get('code') or '').strip()

    if not email or not user_code:
        return error("Email and code are required.", 400)

    try:
        db = get_db()
        ref = db.collection('VerificationCodes').document(email)
        result = _check_code(db.transaction(), ref, user_code, datetime.now(timezone.utc))
    except Exception:
        log.exception("verify-code failed")
        return error("Verification failed. Please try again.", 500)

    messages = {
        "missing": ("No verification code found for this email.", 400),
        "used": ("This code has already been used.", 400),
        "expired": ("Verification code has expired.", 400),
        "locked": ("Too many incorrect attempts. Please request a new code.", 429),
        "invalid": ("Invalid verification code.", 400),
    }
    if result == "ok":
        return jsonify({"success": True, "message": "Email verified successfully!"}), 200
    msg, status = messages[result]
    return error(msg, status)


# ==========================================================================
# 2) PASSWORD OTP helpers  (used by forgot_password.py and change_password.py)
#
# Stored in their own collection (`PasswordOtps`, doc id "reset:<email>" or "change:<email>") so they can
# never be confused with registration verification docs. Codes are stored HASHED. Server-side only.
# Optional: add a Firestore TTL policy on `expires_at` to auto-clean old docs.
# ==========================================================================
PASSWORD_OTP_COLLECTION = "PasswordOtps"
PASSWORD_CODE_TTL = timedelta(minutes=10)
RESET_TOKEN_TTL = timedelta(minutes=10)   # time allowed between verifying the OTP and setting the new password


def _pw_ref(purpose, email):
    return get_db().collection(PASSWORD_OTP_COLLECTION).document(f"{purpose}:{email}")


def _hash(salt, value):
    return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()


def issue_password_otp(purpose, email, uid, subject):
    """Create + email a 6-digit code. Returns False if the per-email cooldown is still active."""
    now = datetime.now(timezone.utc)
    ref = _pw_ref(purpose, email)

    existing = ref.get()
    if existing.exists:
        created = (existing.to_dict() or {}).get("created_at")
        if created and now - as_aware_utc(created) < RESEND_COOLDOWN:
            return False

    code = f"{secrets.randbelow(900000) + 100000}"
    salt = secrets.token_hex(8)
    ref.set({
        "uid": uid,
        "codeHash": _hash(salt, code),
        "salt": salt,
        "created_at": now,
        "expires_at": now + PASSWORD_CODE_TTL,
        "attempts": 0,
        "status": "pending",
    })

    try:
        EmailMessage(
            subject=subject,
            body=(f"Your 6-digit verification code is: {code}\n\n"
                  f"This code expires in {int(PASSWORD_CODE_TTL.total_seconds() // 60)} minutes.\n"
                  "If you did not request this, you can ignore this email and your password will stay the same."),
            to=[email],
        ).send()
    except Exception:
        ref.delete()   # don't leave a cooldown behind for an email that never went out
        raise
    return True


@gcf.transactional
def _check_password_otp(transaction, ref, submitted, now, mode, expected_uid):
    snap = ref.get(transaction=transaction)
    if not snap.exists:
        return "invalid", None
    d = snap.to_dict() or {}
    if d.get("status") != "pending":
        return "invalid", None
    if expected_uid and d.get("uid") != expected_uid:
        return "invalid", None
    if now > as_aware_utc(d["expires_at"]):
        transaction.delete(ref)
        return "invalid", None
    attempts = int(d.get("attempts", 0))
    if attempts >= MAX_ATTEMPTS:
        return "locked", None

    if hmac.compare_digest(d.get("codeHash", ""), _hash(d.get("salt", ""), submitted)):
        if mode == "consume":                       # change-password: single use, done
            transaction.delete(ref)
            return "ok", None
        token = secrets.token_urlsafe(32)           # forgot-password: hand out a short-lived reset token
        transaction.update(ref, {
            "status": "verified",
            "verified_at": now,
            "tokenHash": _hash(d["salt"], token),
        })
        return "ok", token

    transaction.update(ref, {"attempts": attempts + 1})
    return "invalid", None


def verify_password_otp(purpose, email, code, mode="consume", expected_uid=None):
    """Returns (result, token). result is 'ok' | 'invalid' | 'locked'."""
    db = get_db()
    return _check_password_otp(db.transaction(), _pw_ref(purpose, email), str(code).strip(),
                               datetime.now(timezone.utc), mode, expected_uid)


@gcf.transactional
def _consume_reset_token(transaction, ref, token, now):
    snap = ref.get(transaction=transaction)
    if not snap.exists:
        return None
    d = snap.to_dict() or {}
    if d.get("status") != "verified" or not d.get("verified_at"):
        return None
    if now - as_aware_utc(d["verified_at"]) > RESET_TOKEN_TTL:
        transaction.delete(ref)
        return None
    if not hmac.compare_digest(d.get("tokenHash", ""), _hash(d.get("salt", ""), token)):
        return None
    transaction.delete(ref)     # single use
    return d.get("uid")


def consume_reset_token(email, token):
    """Returns the uid if the reset token is valid (and burns it), else None."""
    db = get_db()
    return _consume_reset_token(db.transaction(), _pw_ref("reset", email), token, datetime.now(timezone.utc))


def password_otp_failure(result):
    if result == "locked":
        return error("Too many incorrect attempts. Please request a new code.", 429)
    return error("Invalid or expired code.", 400)