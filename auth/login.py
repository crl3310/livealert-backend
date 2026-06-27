import os
import requests
from flask import request, jsonify
from .register import auth_bp

@auth_bp.route('/login', methods=['POST'])
def login():
    import server  # Grab our live Firestore db connection
    
    # Securely read the Web API key straight from your .env file
    api_key = os.getenv("FIREBASE_WEB_API_KEY")
    
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"success": False, "message": "Missing credentials"}), 400
        
    if not api_key:
        return jsonify({"success": False, "message": "Backend configuration error: Missing API Key."}), 500
        
    try:
        # 1. Hit Firebase's official REST API to verify credentials
        firebase_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        response = requests.post(firebase_url, json=payload)
        res_data = response.json()
        
        # 2. Check if authentication failed
        if response.status_code != 200:
            error_msg = res_data.get('error', {}).get('message', 'Authentication failed')
            if error_msg == "INVALID_LOGIN_CREDENTIALS":
                error_msg = "Invalid email or password."
            return jsonify({"success": False, "message": error_msg}), 401

        uid = res_data.get('localId')
        id_token = res_data.get('idToken')
        
        # 3. Fetch user profile data from Firestore 'Users' collection
        user_profile = {}
        if server.db is not None:
            user_doc = server.db.collection('Users').document(uid).get()
            if user_doc.exists:
                user_profile = user_doc.to_dict()
                if 'birthdate' in user_profile and user_profile['birthdate']:
                    user_profile['birthdate'] = user_profile['birthdate'].strftime('%Y-%m-%d')
        
        return jsonify({
            "success": True,
            "message": "Login successful!",
            "uid": uid,
            "token": id_token,
            "profile": user_profile
        }), 200
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500