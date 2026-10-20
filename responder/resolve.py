import logging
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from google.cloud import firestore

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


def _station_of(call):
    st = call.get('assignedStation') or {}
    return call.get('stationId') or st.get('stationId')


# ---------------------------------------------------------------------------
# STEP 1: close the call. status -> 'resolved' makes listener.py push END_LIVE_SESSION
# to the units and the citizen, so the live stream ends immediately.
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
        if status == 'resolved':  # idempotent: a retry after a network drop is fine
            return 'already_resolved'
        if status in TERMINAL_STATUSES:
            raise _Abort(f"This call is already closed ('{status}') and can't be resolved.", 409)

        txn.update(ref, {
            'status': 'resolved',
            'resolvedAt': datetime.now(timezone.utc),
            'resolvedByUid': g.uid,
            'resolvedByUnitId': profile.get('unitId'),
            'reportStatus': 'pending',  # admin dashboard can filter calls still missing a report
        })
        return 'resolved'

    try:
        result = _txn(db.transaction())
        return jsonify({
            "success": True,
            "message": "Call resolved. Live session ended. Please submit the report.",
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
# STEP 2: short written report for the admin -> 'IncidentReports/<callId>'.
# Body: {
#   "channelName": "<callId>",
#   "report": "what happened / how resolved", required, 10-2000 chars
#   "injuries": 0, "fatalities": 0,          required numbers (0 is allowed)
#   "outcome": "resolved_on_scene",          optional, dropdown (see OUTCOMES)
#   "peopleInvolved": "Juan (victim), Pedro (witness)",   optional, one text box
#   "unitId": "Alpha_1"                      optional
# }
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

    outcome = str(data.get('outcome') or '').strip().lower() or None   # optional
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
    report_ref = db.collection('IncidentReports').document(channel_name)

    @firestore.transactional
    def _txn(txn):
        snap = call_ref.get(transaction=txn)
        if not snap.exists:
            raise _Abort("Active call not found.", 404)
        call = snap.to_dict() or {}
        profile = _authorize(call)

        if str(call.get('status') or '').lower() != 'resolved':
            raise _Abort("Resolve the call first before submitting the report.", 409)

        existing = report_ref.get(transaction=txn)
        old = existing.to_dict() if existing.exists else {}
        if old.get('reviewStatus') == 'reviewed':
            raise _Abort("This report was already reviewed by an admin and can no longer be edited.", 409)

        now = datetime.now(timezone.utc)
        txn.set(report_ref, {
            'report': text,
            'outcome': outcome,
            'peopleInvolved': people or None,
            'injuries': counts['injuries'],
            'fatalities': counts['fatalities'],
            'callId': channel_name,
            'stationId': _station_of(call) or profile.get('stationId'),
            'unitIds': call_unit_ids(call),
            'reportedByUnitId': unit_id or profile.get('unitId'),
            'reportedByUid': g.uid,
            'reporterUuid': call.get('reporterUuid'),  # citizen who made the call
            'callTimestamp': call.get('timestamp'),
            'resolvedAt': call.get('resolvedAt'),
            'reviewStatus': 'pending',                  # admin: pending -> reviewed
            'submittedAt': old.get('submittedAt') or now,
            'updatedAt': now,
        })
        txn.update(call_ref, {'reportStatus': 'submitted', 'reportSubmittedAt': now})
        return bool(old)

    try:
        was_update = _txn(db.transaction())
        return jsonify({
            "success": True,
            "message": "Report updated." if was_update else "Report submitted to admin.",
            "callId": channel_name,
        }), 200
    except _Abort as e:
        return error(e.message, e.code)
    except Exception:
        log.exception("Failed to submit report")
        return error("Failed to submit report.", 500)