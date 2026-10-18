import logging
from datetime import datetime, timedelta, timezone

from firebase_admin import auth
from flask import Blueprint, jsonify, request

from app_core import get_db
from app_security import (MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, as_aware_utc, clean_str, error,
                          limiter, normalize_email, valid_email)

log = logging.getLogger(__name__)

# Initialize Blueprint FIRST so other files can safely import it
auth_bp = Blueprint('auth', __name__)

# A verified email must be used to register within this window.
VERIFICATION_VALID_FOR = timedelta(minutes=30)


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}

    email = normalize_email(data.get('email'))
    password = data.get('password')
    if not email or not isinstance(password, str) or not password:
        return error("Email and password are required", 400)
    if not valid_email(email):
        return error("Please enter a valid email address.", 400)
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        return error(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters long.", 400)

    first_name = clean_str(data.get('firstName'), 100)
    last_name = clean_str(data.get('lastName'), 100)
    address = clean_str(data.get('address'), 300)
    contact_number = clean_str(data.get('contactNumber'), 30)

    # Validate everything BEFORE creating the auth account (the old code left orphan accounts behind).
    birthdate_value = None
    birthdate_str = data.get('birthdate')
    if birthdate_str:
        try:
            birthdate_value = datetime.strptime(str(birthdate_str), "%Y-%m-%d")
        except ValueError:
            return error("Birthdate must be in YYYY-MM-DD format", 400)
        if birthdate_value > datetime.now() or birthdate_value.year < 1900:
            return error("Birthdate is not valid.", 400)

    uid = None
    try:
        db = get_db()
        ver_ref = db.collection('VerificationCodes').document(email)
        ver_doc = ver_ref.get()
        ver = ver_doc.to_dict() if ver_doc.exists else {}
        if not ver.get('verified', False):
            return error("Email address not verified. Please verify your 6-digit code first.", 403,
                         requiresVerification=True)
        verified_at = ver.get('verified_at')
        if not verified_at or datetime.now(timezone.utc) - as_aware_utc(verified_at) > VERIFICATION_VALID_FOR:
            return error("Email verification expired. Please request a new code.", 403,
                         requiresVerification=True)

        try:
            user_record = auth.create_user(email=email, password=password)
        except auth.EmailAlreadyExistsError:
            return error("An account with this email already exists.", 409)
        except ValueError:
            return error("Invalid email or password format.", 400)
        uid = user_record.uid

        db.collection('Users').document(uid).set({
            'address': address,
            'birthdate': birthdate_value,
            'contactNumber': contact_number,
            'email': email,
            'firstName': first_name,
            'lastName': last_name,
            'isVerified': True,
        })

        # The verification is single-use: consume it so it can't be replayed.
        ver_ref.delete()

        return jsonify({
            "success": True,
            "message": "User registered and profile fields populated successfully!",
            "uid": uid
        }), 201

    except Exception:
        log.exception("Registration failed")
        if uid:  # roll back the auth account so the user can retry cleanly
            try:
                auth.delete_user(uid)
            except Exception:
                log.exception("Could not roll back auth user %s", uid)
        return error("Registration failed. Please try again.", 500)


# Import the other auth routes down here to avoid circular dependency errors
from . import verify
