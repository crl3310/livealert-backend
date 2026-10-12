from flask import Blueprint, jsonify
from google.cloud.firestore_v1.base_query import FieldFilter
from google.cloud import firestore

responder_history_bp = Blueprint('responder_history_bp', __name__)

def sanitize_firestore_data(data):
    if isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            if hasattr(value, 'isoformat'):
                new_dict[key] = value.isoformat()
            elif type(value).__name__ == 'GeoPoint':
                new_dict[key] = {
                    "latitude": value.latitude,
                    "longitude": value.longitude
                }
            else:
                new_dict[key] = sanitize_firestore_data(value)
        return new_dict
    elif isinstance(data, list):
        return [sanitize_firestore_data(item) for item in data]
    elif hasattr(data, 'isoformat'):
        return data.isoformat()
    elif type(data).__name__ == 'GeoPoint':
        return {
            "latitude": data.latitude,
            "longitude": data.longitude
        }
    else:
        return data

@responder_history_bp.route('/history/unit/<unit_id>', methods=['GET'])
def get_unit_call_history(unit_id):
    import server
    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    try:
        # Query matching the composite index: assignedStation.unitIds -> status -> timestamp
        query = server.db.collection('ActiveCalls') \
            .where(filter=FieldFilter('assignedStation.unitIds', 'array_contains', unit_id)) \
            .where(filter=FieldFilter('status', 'in', ['resolved', 'fake'])) \
            .order_by('status') \
            .order_by('timestamp', direction=firestore.Query.DESCENDING) \
            .limit(20)

        docs = list(query.stream())
        
        history_list = []
        for doc in docs:
            raw_data = doc.to_dict()
            clean_data = sanitize_firestore_data(raw_data)
            history_list.append(clean_data)

        return jsonify({
            "success": True,
            "count": len(history_list),
            "history": history_list
        }), 200

    except Exception as e:
        print(f"❌ Error in unit history: {str(e)}")
        return jsonify({"success": False, "message": f"Failed to retrieve responder history: {str(e)}"}), 500