from flask import Blueprint, request, jsonify
from firebase_admin import auth, firestore

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    # 1. Grab the entire live server module object to bypass the stale variable cache
    import server 
    
    data = request.get_json() or {}
    
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('firstName', '')
    last_name = data.get('lastName', '')
    address = data.get('address', '')
    contact_number = data.get('contactNumber', '')
    birthdate_str = data.get('birthdate')

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required"}), 400
        
    try:
        # 2. Create user in Firebase Authentication using email/password
        user_record = auth.create_user(email=email, password=password)
        uid = user_record.uid
        
        # 3. Parse birthdate string
        birthdate_value = None
        if birthdate_str:
            try:
                from datetime import datetime
                birthdate_value = datetime.strptime(birthdate_str, "%Y-%m-%d")
            except ValueError:
                return jsonify({"success": False, "message": "Birthdate must be in YYYY-MM-DD format"}), 400

        # 4. Save directly using server.db
        if server.db is not None:
            server.db.collection('Users').document(uid).set({
                'address': address,
                'birthdate': birthdate_value,
                'contactNumber': contact_number,
                'email': email,
                'firstName': first_name,
                'lastName': last_name
            })
        else:
            # Let us know immediately if the db connection didn't initialize globally
            return jsonify({"success": False, "message": "Database client is uninitialized on server."}), 500
        
        return jsonify({
            "success": True, 
            "message": "User registered and profile fields populated successfully!",
            "uid": uid
        }), 201
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400