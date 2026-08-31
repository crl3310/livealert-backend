import os
import requests
from flask import request, jsonify
from google.cloud.firestore import GeoPoint
from .register import auth_bp

def serialize_doc(data):
    """Recursively converts Firestore GeoPoint objects into standard JSON dicts."""
    if not isinstance(data, dict):
        return data
    
    cleaned = {}
    for key, value in data.items():
        if isinstance(value, GeoPoint):
            cleaned[key] = {
                "latitude": value.latitude,
                "longitude": value.longitude
            }
        elif isinstance(value, dict):
            cleaned[key] = serialize_doc(value)
        elif isinstance(value, list):
            cleaned[key] = [serialize_doc(item) if isinstance(item, dict) else item for item in value]
        else:
            cleaned[key] = value
    return cleaned

@auth_bp.route('/responder/login', methods=['POST'])
def responder_login():
    import server

    api_key = os.getenv("FIREBASE_WEB_API_KEY")
    data = request.get_json() or {}
    
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"success": False, "message": "Missing email or password."}), 400

    if not api_key:
        return jsonify({"success": False, "message": "Backend configuration error: Missing API Key."}), 500

    try:
        if server.db is None:
            return jsonify({"success": False, "message": "Database client uninitialized."}), 500

        # 1. Authenticate credentials via Firebase Auth REST API
        firebase_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        response = requests.post(firebase_url, json=payload)
        res_data = response.json()

        if response.status_code != 200:
            error_msg = res_data.get('error', {}).get('message', 'Authentication failed')
            if error_msg == "INVALID_LOGIN_CREDENTIALS":
                error_msg = "Invalid email or password."
            return jsonify({"success": False, "message": error_msg}), 401

        uid = res_data.get('localId')
        id_token = res_data.get('idToken')
        refresh_token = res_data.get('refreshToken')

        # 2. Verify responder role in Firestore
        responder_profile = {}
        responder_doc = server.db.collection('Responders').document(uid).get()

        if responder_doc.exists:
            responder_profile = responder_doc.to_dict()
        else:
            user_doc = server.db.collection('Users').document(uid).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                if user_data.get('role', '').lower() in ['responder', 'commander', 'admin']:
                    responder_profile = user_data
                else:
                    return jsonify({
                        "success": False, 
                        "message": "Access denied. Account is not registered as an emergency responder."
                    }), 403
            else:
                return jsonify({
                    "success": False, 
                    "message": "Responder profile not found."
                }), 404

        # 3. Retrieve assigned Station information
        station_info = None
        station_id = responder_profile.get('stationId')
        if station_id:
            station_doc = server.db.collection('Stations').document(station_id).get()
            if station_doc.exists:
                station_info = station_doc.to_dict()
                station_info['id'] = station_doc.id

        # Clean GeoPoint fields before returning response
        clean_profile = serialize_doc(responder_profile)
        clean_station = serialize_doc(station_info)

        return jsonify({
            "success": True,
            "message": "Responder authenticated successfully.",
            "uid": uid,
            "token": id_token,
            "refreshToken": refresh_token,
            "role": clean_profile.get('role', 'responder'),
            "profile": clean_profile,
            "station": clean_station
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Responder login failed: {str(e)}"}), 500