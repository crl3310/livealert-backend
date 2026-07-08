import os
import time
from datetime import datetime, timezone
from flask import request, jsonify, Blueprint
from agora_token_builder import RtcTokenBuilder

live_bp = Blueprint('live', __name__)

@live_bp.route('/get-token', methods=['POST'])
def get_token():
    import server  # Grab live Firestore database instance from server.py
    
    data = request.get_json() or {}
    channel_name = data.get('channelName')
    reporter_uuid = data.get('uuid')  # Changed from 'email' to 'uuid'
    uid = data.get('uid', 0)          # Clean 0 integer for Agora client routing

    # 1. Validation Check
    if not channel_name or not reporter_uuid:
        return jsonify({"success": False, "message": "channelName and uuid are required."}), 400

    app_id = os.getenv('AGORA_APP_ID')
    app_certificate = os.getenv('AGORA_APP_CERTIFICATE')

    if not app_id or not app_certificate:
        return jsonify({"success": False, "message": "Agora credentials missing in .env file."}), 500

    # 2. Token expiration configuration (Valid for 1 hour)
    expiration_time_in_seconds = 3600
    current_timestamp = int(time.time())
    privilege_expired_ts = current_timestamp + expiration_time_in_seconds

    try:
        # 3. Build the secure RTC token string using the integer UID
        token = RtcTokenBuilder.buildTokenWithUid(
            app_id, 
            app_certificate, 
            channel_name, 
            uid, 
            1, # Role 1 = Publisher/Broadcaster
            privilege_expired_ts
        )

        if server.db is None:
            return jsonify({"success": False, "message": "Database client uninitialized."}), 500

        # 4. Save call details to Firestore tracking the user by their uuid
        server.db.collection('ActiveCalls').document(channel_name).set({
            'channelName': channel_name,
            'reporterUuid': reporter_uuid,  # Preserving your user system's string uuid
            'status': 'incoming',
            'timestamp': datetime.now(timezone.utc)
        })

        # 5. Send information back to the Android client app
        return jsonify({
            "success": True,
            "token": token,
            "channelName": channel_name,
            "uid": uid
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500