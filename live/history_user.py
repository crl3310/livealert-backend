from flask import Blueprint, jsonify
from google.cloud.firestore_v1.base_query import FieldFilter
from google.cloud import firestore
from datetime import timedelta
from firebase_admin import storage

STORAGE_BUCKET = "livealert-d12cc.firebasestorage.app"

history_user_bp = Blueprint('history_user_bp', __name__)

def _signed_image_url(path):
    """Temporary link the app can load, since the Storage files are private."""
    try:
        blob = storage.bucket(STORAGE_BUCKET).blob(path)
        return blob.generate_signed_url(version="v4", expiration=timedelta(hours=1), method="GET")
    except Exception as e:
        print(f"Could not sign image URL for {path}: {e}")
        return None

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
    from flask import request
    
    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    try:
        # 1. Get pagination parameters from query string (e.g., ?page=1&per_page=15)
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=15, type=int)
        
        # Ensure valid numbers
        if page < 1: page = 1
        if per_page < 1: per_page = 15

        combined_history = []

        # 2. Fetch resolved/rejected emergency calls from ActiveCalls
        calls_query = server.db.collection('ActiveCalls') \
            .where(filter=FieldFilter('reporterUuid', '==', uuid)) \
            .where(filter=FieldFilter('status', 'in', ['resolved', 'rejected']))

        for doc in calls_query.stream():
            data = doc.to_dict()
            data['history_type'] = 'call'
            data['id'] = doc.id
            combined_history.append(sanitize_firestore_data(data))

        # 3. Fetch hazard reports submitted by the user
        hazards_query = server.db.collection('Hazards') \
            .where(filter=FieldFilter('reporterUuid', '==', uuid))

        for doc in hazards_query.stream():
            data = doc.to_dict()
            if str(data.get('status', '')).lower() != 'resolved':
                continue
            data['history_type'] = 'hazard'
            data['id'] = doc.id
            combined_history.append(sanitize_firestore_data(data))

        # 4. Sort the combined list by timestamp descending (newest first)
        def get_timestamp(item):
            for key in ['timestamp', 'created_at', 'evidence_uploaded_at']:
                if key in item and item[key]:
                    return item[key]
            return ""

        combined_history.sort(key=get_timestamp, reverse=True)

        # 5. Calculate slice indices for pagination
        total_items = len(combined_history)
        total_pages = (total_items + per_page - 1) // per_page if total_items > 0 else 1
        
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        paginated_history = combined_history[start_idx:end_idx]

        # Attach a temporary photo link to the hazards on this page only
        for item in paginated_history:
            if item.get('history_type') == 'hazard':
                images = item.get('images') or []
                first_path = images[0].get('path') if images and isinstance(images[0], dict) else None
                item['imageUrl'] = _signed_image_url(first_path) if first_path else None

        return jsonify({
            "success": True,
            "page": page,
            "per_page": per_page,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
            "history": paginated_history
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve history: {str(e)}"}), 500