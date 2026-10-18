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
