import logging
from datetime import timedelta

from flask import jsonify

from app_core import get_db, signed_url
from app_security import caller_can_view_call, error, require_auth, valid_channel
from .live import live_bp

log = logging.getLogger(__name__)


def _load_visible_call(channel_name):
    """(call_dict, None) if it exists AND the caller may see it, else (None, error_response).
    Unauthorised callers get 404, so call ids can't be probed."""
    if not valid_channel(channel_name):
        return None, error("Emergency call record not found.", 404)
    doc = get_db().collection('ActiveCalls').document(channel_name).get()
    if not doc.exists:
        return None, error("Emergency call record not found.", 404)
    call = doc.to_dict() or {}
    if not caller_can_view_call(call):
        return None, error("Emergency call record not found.", 404)
    return call, None


@live_bp.route('/track-emergency/<channel_name>', methods=['GET'])
@require_auth
def track_emergency(channel_name):
    try:
        call_data, err = _load_visible_call(channel_name)
        if err:
            return err

        user_location = call_data.get('location', {})
        units_tracking = []
        for unit_id, loc_info in (call_data.get('responderLocations') or {}).items():
            units_tracking.append({
                "unitId": unit_id,
                "latitude": loc_info.get('latitude'),
                "longitude": loc_info.get('longitude'),
                "heading": loc_info.get('heading', 0.0),
                "speed": loc_info.get('speed', 0.0),
                "lastUpdated": loc_info.get('updatedAt')
            })

        return jsonify({
            "success": True,
            "status": call_data.get('status', 'incoming'),
            "userLocation": {
                "latitude": user_location.get('latitude'),
                "longitude": user_location.get('longitude'),
                "address": user_location.get('address', '')
            },
            "assignedUnits": units_tracking
        }), 200

    except Exception:
        log.exception("Failed to retrieve tracking data")
        return error("Failed to retrieve tracking data.", 500)


@live_bp.route('/evidence/<channel_name>', methods=['GET'])
@require_auth
def get_evidence_url(channel_name):
    """NEW: fresh 1-hour link to the (private) evidence video for the reporter or an authorised responder."""
    try:
        call_data, err = _load_visible_call(channel_name)
        if err:
            return err
        path = call_data.get('evidencePath')
        if not path:
            return error("No evidence has been uploaded for this call.", 404)
        url = signed_url(path, timedelta(hours=1))
        if not url:
            return error("Could not generate the evidence link.", 500)
        return jsonify({"success": True, "evidenceUrl": url, "expiresInSeconds": 3600}), 200
    except Exception:
        log.exception("Evidence link failed")
        return error("Could not generate the evidence link.", 500)
