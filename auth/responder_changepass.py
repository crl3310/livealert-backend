import os
import requests
from flask import request, jsonify
from .register import auth_bp

@auth_bp.route('/responder/change-password', methods=['POST'])
def change_password():
    import server  # Access live Firestore db instance

    api_key = os.getenv("FIREBASE_WEB_API_KEY")
    data = request.get_json() or {}

    email = data.get('email')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not email or not old_password or not new_password:
        return jsonify({
            "success": False, 
            "message": "Missing email, old password, or new password."
        }), 400

    if len(new_password) < 6:
        return jsonify({
            "success": False, 
            "message": "New password must be at least 6 characters long."
        }), 400

    try:
        # 1. Re-authenticate user with current password to get ID token
        auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        auth_payload = {
            "email": email,
            "password": old_password,
            "returnSecureToken": True
        }

        auth_res = requests.post(auth_url, json=auth_payload)
        auth_data = auth_res.json()

        if auth_res.status_code != 200:
            return jsonify({
                "success": False, 
                "message": "Invalid current password or email."
            }), 401

        uid = auth_data.get('localId')
        id_token = auth_data.get('idToken')

        # 2. Update password in Firebase Auth REST API
        update_url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        update_payload = {
            "idToken": id_token,
            "password": new_password,
            "returnSecureToken": True
        }

        update_res = requests.post(update_url, json=update_payload)
        if update_res.status_code != 200:
            return jsonify({
                "success": False, 
                "message": "Failed to update password in Firebase Auth."
            }), 500

        # 3. Update is_new to false in Firestore (Responders or Users)
        responder_ref = server.db.collection('Responders').document(uid)
        if responder_ref.get().exists:
            responder_ref.update({"is_new": False})
        else:
            user_ref = server.db.collection('Users').document(uid)
            if user_ref.get().exists:
                user_ref.update({"is_new": False})

        return jsonify({
            "success": True,
            "message": "Password updated successfully. is_new status set to false."
        }), 200

    except Exception as e:
        return jsonify({
            "success": False, 
            "message": f"Change password failed: {str(e)}"
        }), 500