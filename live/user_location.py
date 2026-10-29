import logging
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from google.api_core.exceptions import NotFound
from google.cloud.firestore import GeoPoint

from app_core import get_db
from app_security import TERMINAL_STATUSES, error, parse_coords, require_auth, user_rate_limit, valid_channel

log = logging.getLogger(__name__)
user_location_bp = Blueprint('user_location', __name__)


def _is_call_owner(call):
    # Same field app_security.caller_can_view_call uses to identify the reporter.
    return call.get("reporterUuid") == g.uid


@user_location_bp.route('/location-update', methods=['POST'])
@require_auth()
@user_rate_limit('user_location', 120, 60)
def update_user_location():
    data = request.get_json(silent=True) or {}
    channel_name = data.get('channelName')  # ActiveCall document ID
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    if data.get('uid') and data.get('uid') != g.uid:
        return error("uid does not match the signed-in account.", 403)
    if not channel_name or latitude is None or longitude is None:
        return error("Missing channelName, latitude, or longitude.", 400)
    if not valid_channel(channel_name):
        return error("Invalid channelName.", 400)

    try:
        lat_val, lon_val = parse_coords(latitude, longitude)
        heading = float(data.get('heading', 0.0))   # compass direction (0-360)
        speed = float(data.get('speed', 0.0))
        accuracy = data.get('accuracy')
        accuracy = float(accuracy) if accuracy is not None else None
    except (TypeError, ValueError):
        return error("Invalid coordinates, heading, speed or accuracy.", 400)

    try:
        doc_ref = get_db().collection('ActiveCalls').document(channel_name)
        doc = doc_ref.get()
        if not doc.exists:
            return error("Active call not found.", 404)
        call = doc.to_dict() or {}

        # AUTHORISATION: a user may only update the location of their own report.
        if not _is_call_owner(call):
            return error("You can only update the location of your own report.", 403)

        # GUARD: ignore updates once the session is closed.
        current_status = str(call.get('status') or '').lower()
        if current_status in TERMINAL_STATUSES:
            return jsonify({"success": True, "message": "Session closed. Location update ignored."}), 200

        location = {
            'coordinates': GeoPoint(lat_val, lon_val),
            'latitude': lat_val,
            'longitude': lon_val,
            'heading': heading,
            'speed': speed,
            'updatedByUid': g.uid,
            'updatedAt': datetime.now(timezone.utc),
        }
        if accuracy is not None:
            location['accuracy'] = accuracy

        # Only touches userLocation; status is left alone so listeners aren't re-triggered.
        try:
            doc_ref.update({'userLocation': location})
        except NotFound:
            return error("Active call not found.", 404)

        return jsonify({"success": True, "message": "Location updated."}), 200

    except Exception:
        log.exception("User location update failed")
        return error("Location update failed.", 500)