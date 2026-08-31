import os
from flask import Blueprint, request, jsonify

# Initialize the blueprint here
responder_bp = Blueprint('responder', __name__)


@responder_bp.route('/duty', methods=['POST'])
def update_duty_status():
    import server  # Access live Firestore db instance

    data = request.get_json() or {}
    uid = data.get('uid')
    duty_input = data.get('duty')  # Accepts: "on_duty", "off_duty", "on", "off", or True/False

    if not uid or duty_input is None:
        return jsonify({
            "success": False, 
            "message": "Missing uid or duty status."
        }), 400

    # Normalize input values to "on_duty" or "off_duty"
    if isinstance(duty_input, bool):
        final_duty = "on_duty" if duty_input else "off_duty"
    else:
        val = str(duty_input).lower()
        if val in ['on', 'on_duty', 'online', 'true']:
            final_duty = "on_duty"
        elif val in ['off', 'off_duty', 'offline', 'false']:
            final_duty = "off_duty"
        else:
            return jsonify({
                "success": False, 
                "message": "Invalid duty value. Use 'on_duty' or 'off_duty'."
            }), 400

    try:
        if server.db is None:
            return jsonify({"success": False, "message": "Database client uninitialized."}), 500

        # Check Responders collection first
        responder_ref = server.db.collection('Responders').document(uid)
        
        if responder_ref.get().exists:
            # set with merge=True creates the 'duty' field if it doesn't exist yet
            responder_ref.set({"duty": final_duty}, merge=True)
        else:
            # Fallback check in Users collection
            user_ref = server.db.collection('Users').document(uid)
            if user_ref.get().exists:
                user_ref.set({"duty": final_duty}, merge=True)
            else:
                return jsonify({"success": False, "message": "Responder profile not found."}), 404

        return jsonify({
            "success": True,
            "message": f"Responder duty updated to '{final_duty}'.",
            "duty": final_duty
        }), 200

    except Exception as e:
        return jsonify({
            "success": False, 
            "message": f"Failed to update duty status: {str(e)}"
        }), 500