"""SOS emergency: one tap, no live stream, no Agora, no AI.

Standalone: it does not import anything from live.py. It only writes a normal ActiveCalls document
(same shape as a live report) so the existing admin dashboard picks it up.

Routes:
    POST /sos            create the SOS (or return the one that is already open)
    POST /sos/location   live location ping, called every 5-10 s by the app while the SOS is open
    POST /sos/cancel     reporter cancels an accidental SOS (only before responders are deployed)

Place this file at live/sos.py, then in server.py:
    from live.sos import sos_bp
    app.register_blueprint(sos_bp, url_prefix="/api/live")   # -> /api/live/sos, /api/live/sos/location, ...
"""
import logging
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from app_core import get_db
from .user_location import location_fields, location_update, has_location, parse_motion
from app_security import TERMINAL_STATUSES, as_aware_utc, error, parse_coords, require_auth, user_rate_limit
from .utils import find_nearest_police_station, get_readable_address


log = logging.getLogger(__name__)

sos_bp = Blueprint('sos', __name__)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sos-address")

SOS_INCIDENT_TYPE = "SOS"
SOS_THREAT_LEVEL = 3
SOS_ASSESSMENT = "SOS emergency triggered by the reporter. No live stream or AI analysis performed."
ADDRESS_REFRESH_SEC = 60  # reverse-geocode at most this often while the reporter is moving
SOS_ID_RE = re.compile(r"^sos_[0-9a-f]{8}$")

UNASSIGNED_STATION = {
    "stationName": "Unassigned - No On-Duty Station Available",
    "dispatchStatus": "UNASSIGNED",
}


def _payload():
    """The app may send JSON or form data."""
    return request.get_json(silent=True) or request.form


def _coords(data):
    """(lat, lon) as floats, (None, None) if not sent. Raises ValueError if sent but invalid."""
    lat, lon = data.get("latitude"), data.get("longitude")
    if lat is None or lon is None:
        return None, None
    return parse_coords(str(lat), str(lon))


def _is_open(call):
    return str(call.get("status") or "").lower() not in TERMINAL_STATUSES


def _station_for(lat, lon):
    try:
        return find_nearest_police_station(lat, lon) or UNASSIGNED_STATION
    except Exception:
        log.exception("Nearest-station lookup failed for SOS")
        return UNASSIGNED_STATION


def _fill_address(call_id, lat, lon):
    """Pool task: reverse geocoding can take seconds, so it never delays the SOS."""
    try:
        address = get_readable_address(lat, lon)
        if address:
            get_db().collection("ActiveCalls").document(call_id).update({"location.address": address})
    except Exception:
        log.exception("Address lookup failed for %s", call_id)


def _queue_address(call_id, lat, lon):
    try:
        _executor.submit(_fill_address, call_id, lat, lon)
    except Exception:
        log.exception("Could not queue address lookup for %s", call_id)


def _load_own_sos(call_id):
    """Returns (call_ref, call_dict, error_response). Only the reporter can touch their own SOS."""
    if not call_id or not SOS_ID_RE.match(str(call_id)):
        return None, None, error("Invalid callId.", 400)
    call_ref = get_db().collection("ActiveCalls").document(call_id)
    snap = call_ref.get()
    if not snap.exists:
        return None, None, error(f"SOS '{call_id}' not found.", 404)
    call = snap.to_dict() or {}
    if call.get("reporterUuid") != g.uid or call.get("incidentType") != SOS_INCIDENT_TYPE:
        return None, None, error("Unauthorized: this SOS does not belong to you.", 403)
    return call_ref, call, None


@sos_bp.route("/sos", methods=["POST"])
@require_auth
@user_rate_limit("sos", 10, 3600)
def create_sos():
    data = _payload()
    try:
        lat_val, lon_val = _coords(data)
        motion = parse_motion(data)
    except (TypeError, ValueError):
        return error("Invalid latitude/longitude, heading, speed or accuracy.", 400)

    try:
        db = get_db()

        # One open SOS per user: a double tap or an app retry must not create duplicate alerts.
        mine = (db.collection("ActiveCalls")
                .where(filter=FieldFilter("reporterUuid", "==", g.uid))
                .where(filter=FieldFilter("incidentType", "==", SOS_INCIDENT_TYPE))
                .stream())
        for doc in mine:
            if _is_open(doc.to_dict() or {}):
                return jsonify({"success": True, "callId": doc.id, "alreadyActive": True,
                                "threatLevel": SOS_THREAT_LEVEL,
                                "message": "You already have an active SOS."}), 200

        call_id = f"sos_{uuid.uuid4().hex[:8]}"
        call_ref = db.collection("ActiveCalls").document(call_id)
        now = datetime.now(timezone.utc)

        call_payload = {
            "channelName": None,  # no stream -> dashboard must not show a "Join live" button for SOS
            "reporterUuid": g.uid,
            "status": "incoming",
            "incidentType": SOS_INCIDENT_TYPE,
            "threatLevel": SOS_THREAT_LEVEL,
            "ai_assessment": SOS_ASSESSMENT,
            "timestamp": now,
            "analyzed_at": now,  # set, so it never shows as "AI analysis in progress"
            "aiUnavailable": False,
            "aiScreenRecording": False,
        }
        if lat_val is not None:
            # Everything goes into the existing `location` map (no separate field).
            call_payload["location"] = {
                **location_fields(lat_val, lon_val, g.uid, motion, now),
                "address": "Location found",  # filled in by the address task
            }
            call_payload["assignedStation"] = _station_for(lat_val, lon_val)
        else:
            call_payload["assignedStation"] = UNASSIGNED_STATION

        call_ref.set(call_payload)

        if lat_val is not None:
            _queue_address(call_id, lat_val, lon_val)

        return jsonify({
            "success": True,
            "callId": call_id,
            "alreadyActive": False,
            "threatLevel": SOS_THREAT_LEVEL,
            "locationExpected": lat_val is None,  # True = send /sos/location as soon as GPS is available
            "message": "SOS sent. Keep the app open so responders can follow your location.",
        }), 200

    except Exception:
        log.exception("SOS creation failed")
        return error("Could not send the SOS. Please try again.", 500)


@sos_bp.route("/sos/location", methods=["POST"])
@require_auth
@user_rate_limit("sos-location", 1200, 3600)  # 1 ping / 5 s for 100 min
def update_sos_location():
    data = _payload()
    try:
        lat_val, lon_val = _coords(data)
        motion = parse_motion(data)
    except (TypeError, ValueError):
        return error("Invalid latitude/longitude, heading, speed or accuracy.", 400)
    if lat_val is None:
        return error("latitude and longitude are required.", 400)

    call_ref, call, err = _load_own_sos(data.get("callId"))
    if err:
        return err

    # Resolved/cancelled -> tell the app to stop tracking.
    if not _is_open(call):
        return jsonify({"success": True, "active": False, "status": call.get("status")}), 200

    try:
        now = datetime.now(timezone.utc)
        # Updates only the position keys inside `location`; location.address is preserved.
        update = location_update(lat_val, lon_val, g.uid, motion, now)

        # The SOS was sent before GPS was ready: pick the nearest station now.
        if not has_location(call):
            update["assignedStation"] = _station_for(lat_val, lon_val)

        last_addr = call.get("addressUpdatedAt")
        refresh_address = (not last_addr
                           or (now - as_aware_utc(last_addr)).total_seconds() >= ADDRESS_REFRESH_SEC)
        if refresh_address:
            update["addressUpdatedAt"] = now

        call_ref.update(update)

        if refresh_address:
            _queue_address(call_ref.id, lat_val, lon_val)

        return jsonify({"success": True, "active": True}), 200

    except Exception:
        log.exception("SOS location update failed for %s", call_ref.id)
        return error("Could not update the location.", 500)


@sos_bp.route("/sos/cancel", methods=["POST"])
@require_auth
@user_rate_limit("sos-cancel", 20, 3600)
def cancel_sos():
    """For accidental SOS. Once responders are deployed only the dispatcher can close it."""
    call_ref, _, err = _load_own_sos(_payload().get("callId"))
    if err:
        return err

    @firestore.transactional
    def _txn(txn):
        snap = call_ref.get(transaction=txn)
        call = (snap.to_dict() or {}) if snap.exists else None
        if call is None:
            return "gone"
        if not _is_open(call):
            return "closed"
        if call.get("deployedUnits") or call.get("deployedResponders"):
            return "deployed"
        txn.update(call_ref, {"status": "cancelled", "endedAt": datetime.now(timezone.utc)})
        return "ok"

    try:
        result = _txn(get_db().transaction())
    except Exception:
        log.exception("SOS cancel failed for %s", call_ref.id)
        return error("Could not cancel the SOS. Please try again.", 500)

    if result == "gone":
        return error("This SOS no longer exists.", 404)
    if result == "deployed":
        return error("Responders are already on the way. Please contact the dispatcher to close this SOS.", 409)
    if result == "closed":
        return jsonify({"success": True, "message": "This SOS is already closed."}), 200
    return jsonify({"success": True, "message": "SOS cancelled."}), 200