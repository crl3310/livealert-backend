from flask import Blueprint, request, jsonify
from firebase_admin import auth, firestore

# Initialize Blueprint FIRST so other files can safely import it
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    # Grab the entire live server module object to bypass the stale variable cache
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
        if server.db is None:
            return jsonify({"success": False, "message": "Database client is uninitialized on server."}), 500

        # --- Security Check: Force Email Verification First ---
        verify_doc = server.db.collection('VerificationCodes').document(email).get()
        if not verify_doc.exists or not verify_doc.to_dict().get('verified', False):
            return jsonify({
                "success": False, 
                "message": "Email address not verified. Please verify your 6-digit code first."
            }), 403
        
        # Create user in Firebase Authentication using email/password
        user_record = auth.create_user(email=email, password=password)
        uid = user_record.uid
        
        # Parse birthdate string
        birthdate_value = None
        if birthdate_str:
            try:
                from datetime import datetime
                birthdate_value = datetime.strptime(birthdate_str, "%Y-%m-%d")
            except ValueError:
                return jsonify({"success": False, "message": "Birthdate must be in YYYY-MM-DD format"}), 400

        # Save profile directly inside Firestore
        server.db.collection('Users').document(uid).set({
            'address': address,
            'birthdate': birthdate_value,
            'contactNumber': contact_number,
            'email': email,
            'firstName': first_name,
            'lastName': last_name,
            'isVerified': True # Explicitly record status on their profile
        })
        
        return jsonify({
            "success": True, 
            "message": "User registered and profile fields populated successfully!",
            "uid": uid
        }), 201
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

# --- FIX: Import verification paths down here down below to completely prevent circular dependency errors ---
from . import verify