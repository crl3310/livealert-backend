import logging

from flask import Blueprint, g, jsonify
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from app_core import get_db
from app_security import (GLOBAL_ADMIN_ROLES, UNIT_RE, error, get_profile, profile_role, require_auth)

log = logging.getLogger(__name__)
responder_history_bp = Blueprint('responder_history_bp', __name__)


def sanitize_firestore_data(data):
    if isinstance(data, dict):
        return {k: sanitize_firestore_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_firestore_data(item) for item in data]
    if hasattr(data, 'isoformat'):
        return data.isoformat()
    if type(data).__name__ == 'GeoPoint':
        return {"latitude": data.latitude, "longitude": data.longitude}
    return data


def _may_view_unit(unit_id):
    _, profile = get_profile()
    role = profile_role()
    if role in GLOBAL_ADMIN_ROLES:
        return True
    if unit_id in (profile.get('unitId'), g.uid):
        return True
    if role in ('responder_admin', 'commander'):  # station-level admins: units of their own station
        unit_doc = get_db().collection('Units').document(unit_id).get()
        station = (unit_doc.to_dict() or {}).get('stationId') if unit_doc.exists else None
        return bool(station) and str(station).upper() == str(profile.get('stationId') or '').upper()
    return False


@responder_history_bp.route('/history/unit/<unit_id>', methods=['GET'])
@require_auth(responder=True)
def get_unit_call_history(unit_id):
    if not UNIT_RE.match(unit_id) or not _may_view_unit(unit_id):
        return error("You are not allowed to view this unit's history.", 403)

    try:
        # Query matching the composite index: assignedStation.unitIds -> status -> timestamp
        query = get_db().collection('ActiveCalls') \
            .where(filter=FieldFilter('assignedStation.unitIds', 'array_contains', unit_id)) \
            .where(filter=FieldFilter('status', 'in', ['resolved', 'fake'])) \
            .order_by('status') \
            .order_by('timestamp', direction=firestore.Query.DESCENDING) \
            .limit(20)

        history_list = [sanitize_firestore_data(doc.to_dict()) for doc in query.stream()]
        return jsonify({"success": True, "count": len(history_list), "history": history_list}), 200

    except Exception:
        log.exception("Error in unit history")
        return error("Failed to retrieve responder history.", 500)
