import logging
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from google.api_core.exceptions import NotFound
from google.cloud import firestore
from google.cloud.firestore import GeoPoint

from app_core import get_db
from app_security import TERMINAL_STATUSES, error, parse_coords, require_auth, user_rate_limit, valid_channel

log = logging.getLogger(__name__)
user_location_bp = Blueprint('user_location', __name__)

LOCATION_FIELD = "location"


# ---------------------------------------------------------------------------
# Shared location helpers. sos.py imports these too, so /location-update, /sos and
# /sos/location all write the reporter's position into the SAME existing `location` map:
#   location.coordinates (GeoPoint), latitude, longitude, updatedByUid, updatedAt,
#   plus heading / speed / accuracy when the app sends them.
# The reverse-geocoded address stays at `location.address` and is never overwritten here.
# No separate field (like the old `userLocation`) is created.
# ---------------------------------------------------------------------------
def parse_motion(data):
    """Optional heading / speed / accuracy as floats. Missing or empty values are skipped.

    Raises ValueError/TypeError if a value is sent but is not a number.
    """
    motion = {}
    for key in ("heading", "speed", "accuracy"):
        value = data.get(key)
        if value is None or value == "":
            continue
        motion[key] = float(value)
    return motion


def location_fields(lat, lon, uid, motion=None, now=None):
    """Position fields that live inside the existing `location` map (flat, no prefix).

    The reverse-geocoded `address` is not included; it is written separately.
    """
    fields = {
        "coordinates": GeoPoint(lat, lon),
        "latitude": lat,
        "longitude": lon,
        "updatedByUid": uid,
        "updatedAt": now or datetime.now(timezone.utc),
    }
    fields.update(motion or {})
    return fields


def location_update(lat, lon, uid, motion=None, now=None):
    """Dict for doc_ref.update(): sets each field as `location.<field>`.

    Dotted paths only touch those keys, so `location.address` is preserved.
    """
    update = {f"{LOCATION_FIELD}.{k}": v
              for k, v in location_fields(lat, lon, uid, motion, now).items()}
    # Cleanup: removes the legacy `userLocation` field from older documents on their next ping.
    # Safe to delete this line once no old documents remain.
    update["userLocation"] = firestore.DELETE_FIELD
    return update


def has_location(call):
    """True if the call already has coordinates inside `location`."""
    return (call.get(LOCATION_FIELD) or {}).get("coordinates") is not None


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
        motion = parse_motion(data)  # optional heading (0-360), speed, accuracy
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

        # Only touches the position keys inside `location` (same ones /sos uses);
        # location.address and status are left alone so listeners aren't re-triggered.
        try:
            doc_ref.update(location_update(lat_val, lon_val, g.uid, motion))
        except NotFound:
            return error("Active call not found.", 404)

        return jsonify({"success": True, "message": "Location updated."}), 200

    except Exception:
        log.exception("User location update failed")
        return error("Location update failed.", 500)