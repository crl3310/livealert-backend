from flask import Blueprint, request, jsonify

# Inside your live or citizen blueprint file
@live_bp.route('/track-emergency/<channel_name>', methods=['GET'])
def track_emergency(channel_name):
    import server

    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    try:
        doc_ref = server.db.collection('ActiveCalls').document(channel_name).get()

        if not doc_ref.exists:
            return jsonify({"success": False, "message": "Emergency call record not found."}), 404

        call_data = doc_ref.to_dict()

        # 1. Extract citizen's stationary location
        user_location = call_data.get('location', {})

        # 2. Extract responding units locations map
        responder_locations_map = call_data.get('responderLocations', {})

        # Format responder locations into a clean list for the mobile app UI
        units_tracking = []
        for unit_id, loc_info in responder_locations_map.items():
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

    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve tracking data: {str(e)}"}), 500