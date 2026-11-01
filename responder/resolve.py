import logging
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from app_core import get_db
from app_security import (GLOBAL_ADMIN_ROLES, TERMINAL_STATUSES, UNIT_RE, call_unit_ids, error, get_profile,
                         profile_role, require_auth, responder_can_access_call, user_rate_limit, valid_channel)

log = logging.getLogger(__name__)
responder_resolve_bp = Blueprint('responder_resolve', __name__)

MIN_REPORT_LEN = 10
MAX_REPORT_LEN = 2000
MAX_PEOPLE_LEN = 500
OUTCOMES = {'resolved_on_scene', 'transported_to_hospital', 'arrest_made', 'referred', 'unfounded', 'other'}
STATION_ADMIN_ROLES = {'responder_admin', 'commander'}  # may act on any call at their own station


class _Abort(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.message, self.code = message, code


def _authorize(call):
    """Admins/station admins: any call they can access. Regular responders: only their assigned unit."""
    if not responder_can_access_call(call):
        raise _Abort("You are not assigned to this call.", 403)
    _, profile = get_profile()
    if profile_role() in GLOBAL_ADMIN_ROLES | STATION_ADMIN_ROLES:
        return profile  # station match already verified by responder_can_access_call
    assigned = call_unit_ids(call)
    my_unit = profile.get('unitId')
    if assigned and my_unit not in assigned and g.uid not in assigned:
        raise _Abort("Your unit is not assigned to this call.", 403)
    return profile


def _authorize_report(call):
    """Reports are filed later, after the responder may have moved on to another emergency.
    The responder who closed the call may always file its report, even if the call's
    unit/station assignment has since changed. Everyone else goes through _authorize."""
    _, profile = get_profile()
    if call.get('resolvedByUid') == g.uid:
        return profile
    return _authorize(call)


def _station_of(call):
    st = call.get('assignedStation') or {}
    return call.get('stationId') or st.get('stationId')


def _get_responder_name(profile):
    """Safely extracts and formats the responder's name from multiple profile schema variations."""
    first = profile.get('firstName', '').strip()
    last = profile.get('lastName', '').strip()
    return f"{first} {last}".strip() or profile.get('name') or profile.get('fullName') or 'Unknown Responder'


# ---------------------------------------------------------------------------
# STEP 1: Close the call. Records resolver UID, Unit, and Name.
# ---------------------------------------------------------------------------
@responder_resolve_bp.route('/resolve', methods=['POST'])
@require_auth(responder=True)
@user_rate_limit('resolve', 20, 60)
def resolve_call():
    data = request.get_json(silent=True) or {}
    channel_name = data.get('channelName')  # ActiveCall document ID
    if not valid_channel(channel_name):
        return error("Missing or invalid channelName.", 400)

    db = get_db()
    ref = db.collection('ActiveCalls').document(channel_name)

    @firestore.transactional
    def _txn(txn):
        snap = ref.get(transaction=txn)
        if not snap.exists:
            raise _Abort("Active call not found.", 404)
        call = snap.to_dict() or {}
        profile = _authorize(call)

        status = str(call.get('status') or '').lower()
        if status == 'resolved':  
            return 'already_resolved'
        if status in TERMINAL_STATUSES:
            raise _Abort(f"This call is already closed ('{status}') and can't be resolved.", 409)

        responder_name = _get_responder_name(profile)

        txn.update(ref, {
            'status': 'resolved',
            'resolvedAt': datetime.now(timezone.utc),
            'resolvedByUid': g.uid,
            'resolvedByUnitId': profile.get('unitId'),
            'resolvedByName': responder_name,
            'reportStatus': 'pending',  
        })
        return 'resolved'

    try:
        result = _txn(db.transaction())
        return jsonify({
            "success": True,
            "message": "Call resolved. Live session ended. The report can be submitted now or later.",
            "alreadyResolved": result == 'already_resolved',
            "reportRequired": True,
            "callId": channel_name,
        }), 200
    except _Abort as e:
        return error(e.message, e.code)
    except Exception:
        log.exception("Failed to resolve call")
        return error("Failed to resolve call.", 500)


# ---------------------------------------------------------------------------
# STEP 2: Submit report under the 'IncidentReport' subdocument inside ActiveCalls
# ---------------------------------------------------------------------------
@responder_resolve_bp.route('/report', methods=['POST'])
@require_auth(responder=True)
@user_rate_limit('report', 20, 60)
def submit_report():
    data = request.get_json(silent=True) or {}
    channel_name = data.get('channelName')
    if not valid_channel(channel_name):
        return error("Missing or invalid channelName.", 400)

    unit_id = data.get('unitId')
    if unit_id is not None and (not isinstance(unit_id, str) or not UNIT_RE.match(unit_id)):
        return error("Invalid unitId.", 400)

    text = data.get('report')
    if not isinstance(text, str) or len(text.strip()) < MIN_REPORT_LEN:
        return error(f"Please write a short report (at least {MIN_REPORT_LEN} characters).", 400)
    text = text.strip()
    if len(text) > MAX_REPORT_LEN:
        return error(f"Report is too long (max {MAX_REPORT_LEN} characters).", 400)

    outcome = str(data.get('outcome') or '').strip().lower() or None   
    if outcome and outcome not in OUTCOMES:
        return error(f"Invalid outcome. Use one of: {', '.join(sorted(OUTCOMES))}.", 400)

    people = data.get('peopleInvolved')
    if people is not None and not isinstance(people, str):
        return error("'peopleInvolved' must be text.", 400)
    people = (people or '').strip()
    if len(people) > MAX_PEOPLE_LEN:
        return error(f"'peopleInvolved' is too long (max {MAX_PEOPLE_LEN} characters).", 400)

    counts = {}
    for field in ('injuries', 'fatalities'):
        raw = data.get(field)
        if raw is None or raw == '':
            return error(f"'{field}' is required (enter 0 if none).", 400)
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return error(f"'{field}' must be a whole number.", 400)
        if n < 0 or n > 1000:
            return error(f"'{field}' is out of range.", 400)
        counts[field] = n

    db = get_db()
    call_ref = db.collection('ActiveCalls').document(channel_name)

    @firestore.transactional
    def _txn(txn):
        snap = call_ref.get(transaction=txn)
        if not snap.exists:
            raise _Abort("Active call not found.", 404)
        call = snap.to_dict() or {}
        profile = _authorize_report(call)

        if str(call.get('status') or '').lower() != 'resolved':
            raise _Abort("Resolve the call first before submitting the report.", 409)

        existing_report = call.get('IncidentReport') or {}
        now = datetime.now(timezone.utc)
        was_update = bool(existing_report)
        responder_name = _get_responder_name(profile)

        # Store all report info inside the 'IncidentReport' map subdocument
        txn.update(call_ref, {
            'IncidentReport': {
                'report': text,
                'outcome': outcome,
                'peopleInvolved': people or None,
                'injuries': counts['injuries'],
                'fatalities': counts['fatalities'],
                'stationId': _station_of(call) or profile.get('stationId'),
                'unitIds': call_unit_ids(call),
                'reportedByUnitId': unit_id or profile.get('unitId'),
                'reportedByUid': g.uid,
                'reportedByName': responder_name,
                'submittedAt': existing_report.get('submittedAt') or now,
                'updatedAt': now,
            },
            'reportStatus': 'submitted',
            'reportSubmittedAt': now
        })
        return was_update

    try:
        was_update = _txn(db.transaction())
        return jsonify({
            "success": True,
            "message": "IncidentReport updated." if was_update else "IncidentReport submitted successfully.",
            "callId": channel_name,
        }), 200
    except _Abort as e:
        return error(e.message, e.code)
    except Exception:
        log.exception("Failed to submit report")
        return error("Failed to submit report.", 500)

# ---------------------------------------------------------------------------
# STEP 1.5: List calls this responder closed but hasn't filed a report for yet.
# The app uses this to show "pending reports" so a report can be filled in later
# (after another emergency, an app restart, a shift handover on the same device, etc.).
# ---------------------------------------------------------------------------
@responder_resolve_bp.route('/reports/pending', methods=['GET'])
@require_auth(responder=True)
@user_rate_limit('pending_reports', 30, 60)
def pending_reports():
    try:
        db = get_db()
        snaps = (db.collection('ActiveCalls')
                   .where(filter=FieldFilter('resolvedByUid', '==', g.uid))
                   .where(filter=FieldFilter('reportStatus', '==', 'pending'))
                   .limit(50)
                   .stream())

        items = []
        for snap in snaps:
            call = snap.to_dict() or {}
            resolved_at = call.get('resolvedAt')
            items.append({
                "callId": snap.id,
                "resolvedAt": resolved_at.isoformat() if hasattr(resolved_at, 'isoformat') else None,
                "stationId": _station_of(call),
                "unitIds": call_unit_ids(call),
                "incidentType": call.get('incidentType'),
                "address": (call.get('location') or {}).get('address'),
            })

        items.sort(key=lambda i: i["resolvedAt"] or "", reverse=True)
        return jsonify({"success": True, "count": len(items), "pending": items}), 200
    except Exception:
        log.exception("Failed to list pending reports")
        return error("Failed to load pending reports.", 500)