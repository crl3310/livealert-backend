import logging
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from google.api_core.exceptions import NotFound
from google.cloud.firestore import GeoPoint

from app_core import get_db
from app_security import (GLOBAL_ADMIN_ROLES, TERMINAL_STATUSES, UNIT_RE, call_unit_ids, error, get_profile,
                          parse_coords, profile_role, require_auth, responder_can_access_call, user_rate_limit,
                          valid_channel)

log = logging.getLogger(__name__)
responder_bp = Blueprint('responder_location', __name__)


@responder_bp.route('/location-update', methods=['POST'])
@require_auth(responder=True)
@user_rate_limit('location', 120, 60)
def update_location():
    data = request.get_json(silent=True) or {}
    channel_name = data.get('channelName')  # ActiveCall document ID
    unit_id = data.get('unitId')            # Unit ID (e.g., "Alpha_1")
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    if data.get('uid') and data.get('uid') != g.uid:
        return error("uid does not match the signed-in account.", 403)
    if not channel_name or not unit_id or latitude is None or longitude is None:
        return error("Missing channelName, unitId, latitude, or longitude.", 400)
    if not valid_channel(channel_name) or not isinstance(unit_id, str) or not UNIT_RE.match(unit_id):
        return error("Invalid channelName or unitId.", 400)

    try:
        lat_val, lon_val = parse_coords(latitude, longitude)
        heading = float(data.get('heading', 0.0))   # compass direction (0-360)
        speed = float(data.get('speed', 0.0))
    except (TypeError, ValueError):
        return error("Invalid coordinates, heading or speed.", 400)

    try:
        doc_ref = get_db().collection('ActiveCalls').document(channel_name)
        doc = doc_ref.get()
        if not doc.exists:
            return error("Active call not found.", 404)
        call = doc.to_dict() or {}

        # AUTHORISATION: must be allowed on this call, and may only report for their own unit.
        _, profile = get_profile()
        if not responder_can_access_call(call):
            return error("You are not assigned to this call.", 403)
        if profile_role() not in GLOBAL_ADMIN_ROLES and unit_id not in (profile.get('unitId'), g.uid):
            return error("You can only report the location of your own unit.", 403)
        assigned_units = call_unit_ids(call)
        if assigned_units and unit_id not in assigned_units:
            return error("This unit is not assigned to the call.", 403)

        # GUARD: ignore updates once the session is closed ('rejected' was missing before: it let a
        # GPS ping flip a rejected call back to en_route).
        current_status = str(call.get('status') or '').lower()
        if current_status in TERMINAL_STATUSES:
            return jsonify({"success": True, "message": "Session closed. Location update ignored."}), 200

        update = {
            f'responderLocations.{unit_id}': {
                'coordinates': GeoPoint(lat_val, lon_val),
                'latitude': lat_val,
                'longitude': lon_val,
                'heading': heading,
                'speed': speed,
                'updatedByUid': g.uid,
                'updatedAt': datetime.now(timezone.utc),
            }
        }
        if current_status != 'en_route':   # avoid rewriting status (and re-triggering listeners) on every ping
            update['status'] = 'en_route'

        try:
            doc_ref.update(update)
        except NotFound:
            return error("Active call not found.", 404)

        return jsonify({"success": True, "message": f"Location updated for unit {unit_id}."}), 200

    except Exception:
        log.exception("Location update failed")
        return error("Location update failed.", 500)
