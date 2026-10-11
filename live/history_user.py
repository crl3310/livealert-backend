from flask import Blueprint, jsonify
from google.cloud.firestore_v1.base_query import FieldFilter
from google.cloud import firestore

history_user_bp = Blueprint('history_user_bp', __name__)

def sanitize_firestore_data(data):
    """Recursively converts Firestore timestamps, GeoPoints, and special types into JSON-serializable formats."""
    if isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            # Convert timestamp-like objects
            if hasattr(value, 'isoformat'):
                new_dict[key] = value.isoformat()
            # Convert GeoPoint objects by class name
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

@history_user_bp.route('/history/user/<uuid>', methods=['GET'])
def get_user_call_history(uuid):
    import server
    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    try:
        query = server.db.collection('ActiveCalls') \
            .where(filter=FieldFilter('reporterUuid', '==', uuid)) \
            .where(filter=FieldFilter('status', 'in', ['resolved', 'rejected'])) \
            .order_by('timestamp', direction=firestore.Query.DESCENDING) \
            .limit(20)

        docs = query.stream()
        history_list = []
        for doc in docs:
            raw_data = doc.to_dict()
            # Safely sanitize all nested fields (GeoPoints, Timestamps, etc.)
            clean_data = sanitize_firestore_data(raw_data)
            history_list.append(clean_data)

        return jsonify({
            "success": True,
            "count": len(history_list),
            "history": history_list
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve history: {str(e)}"}), 500