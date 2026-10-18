import logging

from flask import Blueprint, g, jsonify, request

from app_core import get_db
from app_security import error, get_profile, require_auth, user_rate_limit

log = logging.getLogger(__name__)

# Initialize the blueprint here
responder_bp = Blueprint('responder', __name__)


@responder_bp.route('/duty', methods=['POST'])
@require_auth(responder=True)
@user_rate_limit('duty', 30, 60)
def update_duty_status():
    data = request.get_json(silent=True) or {}
    duty_input = data.get('duty')  # Accepts: "on_duty", "off_duty", "on", "off", or True/False

    # A responder can only change THEIR OWN duty. (Previously any caller could flip anyone's duty,
    # which controls which stations receive emergency calls.)
    body_uid = data.get('uid')
    if body_uid and body_uid != g.uid:
        return error("You can only change your own duty status.", 403)

    if duty_input is None:
        return error("Missing duty status.", 400)

    if isinstance(duty_input, bool):
        final_duty = "on_duty" if duty_input else "off_duty"
    else:
        val = str(duty_input).lower()
        if val in ['on', 'on_duty', 'online', 'true']:
            final_duty = "on_duty"
        elif val in ['off', 'off_duty', 'offline', 'false']:
            final_duty = "off_duty"
        else:
            return error("Invalid duty value. Use 'on_duty' or 'off_duty'.", 400)

    try:
        coll, _ = get_profile()
        if not coll:
            return error("Responder profile not found.", 404)
        get_db().collection(coll).document(g.uid).set({"duty": final_duty}, merge=True)
        return jsonify({"success": True, "message": f"Responder duty updated to '{final_duty}'.",
                        "duty": final_duty}), 200
    except Exception:
        log.exception("Failed to update duty status")
        return error("Failed to update duty status.", 500)
