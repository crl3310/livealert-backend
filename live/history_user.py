import logging
from datetime import timedelta

from flask import Blueprint, g, jsonify, request
from google.cloud.firestore_v1.base_query import FieldFilter

from app_core import get_db, signed_url
from app_security import GLOBAL_ADMIN_ROLES, error, is_responder, profile_role, require_auth

log = logging.getLogger(__name__)
history_user_bp = Blueprint('history_user_bp', __name__)

MAX_PER_PAGE = 50


def sanitize_firestore_data(data):
    """Recursively converts Firestore timestamps, GeoPoints, and special types into JSON-serializable formats."""
    if isinstance(data, dict):
        return {k: sanitize_firestore_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_firestore_data(item) for item in data]
    if hasattr(data, 'isoformat'):
        return data.isoformat()
    if type(data).__name__ == 'GeoPoint':
        return {"latitude": data.latitude, "longitude": data.longitude}
    return data


@history_user_bp.route('/history/user/<uuid>', methods=['GET'])
@require_auth
def get_user_call_history(uuid):
    # Users may only read their OWN history (this was an open IDOR: any uuid returned anyone's data).
    if uuid != g.uid and not (is_responder() and profile_role() in GLOBAL_ADMIN_ROLES):
        return error("You can only view your own history.", 403)

    try:
        db = get_db()
        page = max(request.args.get('page', default=1, type=int), 1)
        per_page = request.args.get('per_page', default=15, type=int)
        if per_page < 1:
            per_page = 15
        per_page = min(per_page, MAX_PER_PAGE)

        combined_history = []

        calls_query = db.collection('ActiveCalls') \
            .where(filter=FieldFilter('reporterUuid', '==', uuid)) \
            .where(filter=FieldFilter('status', 'in', ['resolved', 'rejected']))
        for doc in calls_query.stream():
            data = doc.to_dict()
            data['history_type'] = 'call'
            data['id'] = doc.id
            combined_history.append(sanitize_firestore_data(data))

        hazards_query = db.collection('Hazards').where(filter=FieldFilter('reporterUuid', '==', uuid))
        for doc in hazards_query.stream():
            data = doc.to_dict()
            if str(data.get('status', '')).lower() != 'resolved':
                continue
            data['history_type'] = 'hazard'
            data['id'] = doc.id
            combined_history.append(sanitize_firestore_data(data))

        def get_timestamp(item):
            for key in ['timestamp', 'created_at', 'evidence_uploaded_at']:
                if key in item and item[key]:
                    return item[key]
            return ""

        combined_history.sort(key=get_timestamp, reverse=True)

        total_items = len(combined_history)
        total_pages = (total_items + per_page - 1) // per_page if total_items > 0 else 1
        start_idx = (page - 1) * per_page
        paginated_history = combined_history[start_idx:start_idx + per_page]

        # Temporary links for private files, only for the items on this page.
        for item in paginated_history:
            if item.get('history_type') == 'hazard':
                images = item.pop('images', None) or []
                first_path = images[0].get('path') if images and isinstance(images[0], dict) else None
                item['imageUrl'] = signed_url(first_path) if first_path else None
            elif item.get('evidencePath'):
                item['evidenceUrl'] = signed_url(item['evidencePath'], timedelta(hours=1))

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

    except Exception:
        log.exception("Failed to retrieve user history")
        return error("Failed to retrieve history.", 500)
