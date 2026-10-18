import logging
import uuid

from firebase_admin import messaging
from flask import jsonify, request
from google.cloud.firestore import GeoPoint

from app_core import get_db
from app_security import RESPONDER_ROLES, error, firebase_sign_in, limiter, normalize_email
from .register import auth_bp

log = logging.getLogger(__name__)


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


@auth_bp.route('/responder/login', methods=['POST'])
@limiter.limit("10 per minute; 100 per hour")
def responder_login():
    data = request.get_json(silent=True) or {}

    email = normalize_email(data.get('email'))
    password = data.get('password')
    fcm_token = data.get('fcmToken')  # optional
    duty_status = data.get('duty')    # optional duty status override

    if not email or not isinstance(password, str) or not password:
        return error("Missing email or password.", 400)
    if fcm_token is not None and (not isinstance(fcm_token, str) or len(fcm_token) > 4096):
        return error("Invalid fcmToken.", 400)

    try:
        db = get_db()

        # 1. Authenticate credentials via Firebase Auth REST API
        res_data, fail = firebase_sign_in(email, password)
        if fail:
            return error(fail[0], fail[1])

        uid = res_data.get('localId')
        id_token = res_data.get('idToken')
        refresh_token = res_data.get('refreshToken')

        # 2. Verify responder role in Firestore
        profile_ref = db.collection('Responders').document(uid)
        responder_doc = profile_ref.get()

        if responder_doc.exists:
            responder_profile = responder_doc.to_dict() or {}
        else:
            profile_ref = db.collection('Users').document(uid)   # write back to the SAME collection we read from
            user_doc = profile_ref.get()
            if not user_doc.exists:
                return error("Responder profile not found.", 404)
            user_data = user_doc.to_dict() or {}
            if str(user_data.get('role', '')).lower() not in RESPONDER_ROLES:
                return error("Access denied. Account is not registered as an emergency responder.", 403)
            responder_profile = user_data

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
