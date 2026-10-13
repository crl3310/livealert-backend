from flask import Blueprint, request, jsonify
from google.cloud.firestore import GeoPoint
from datetime import datetime, timezone

responder_bp = Blueprint('responder_location', __name__)

@responder_bp.route('/location-update', methods=['POST'])
def update_location():
    import server

    data = request.get_json() or {}
    channel_name = data.get('channelName')  # ActiveCall document ID
    unit_id = data.get('unitId')            # Unit ID (e.g., "Alpha_1")
    uid = data.get('uid')                   # Responder UID
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    heading = data.get('heading', 0.0)      # Compass direction (0-360)
    speed = data.get('speed', 0.0)          # Speed in m/s or km/h

    if not channel_name or not unit_id or not uid or latitude is None or longitude is None:
        return jsonify({"success": False, "message": "Missing channelName, unitId, uid, latitude, or longitude."}), 400

    try:
        if server.db is None:
            return jsonify({"success": False, "message": "Database client uninitialized."}), 500

        doc_ref = server.db.collection('ActiveCalls').document(channel_name)
        doc = doc_ref.get()

        # GUARD CLAUSE: Ignore location updates if the emergency session is already closed
        if doc.exists:
            current_status = doc.to_dict().get('status')
            if current_status in ['resolved', 'cancelled', 'cancelled_fake', 'fake']:
                return jsonify({"success": True, "message": "Session closed. Location update ignored."}), 200

        lat_val = float(latitude)
        lon_val = float(longitude)

        # Update unit location under responderLocations.<unitId>
        unit_location_data = {
            f'responderLocations.{unit_id}': {
                'coordinates': GeoPoint(lat_val, lon_val),
                'latitude': lat_val,
                'longitude': lon_val,
                'heading': float(heading),
                'speed': float(speed),
                'updatedByUid': uid,
                'updatedAt': datetime.now(timezone.utc)
            },
            'status': 'en_route'
        }

        # Save to ActiveCalls in Firestore
        doc_ref.update(unit_location_data)

        return jsonify({
            "success": True,
            "message": f"Location updated for unit {unit_id}."
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Location update failed: {str(e)}"}), 500