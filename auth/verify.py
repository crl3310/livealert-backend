import random
from datetime import datetime, timedelta, timezone
from flask import request, jsonify
from flask_mailman import EmailMessage
from .register import auth_bp

@auth_bp.route('/send-verification', methods=['POST'])
def send_verification():
    import server  # Grab live Firestore instance
    
    data = request.get_json() or {}
    email = data.get('email')
    
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400
        
    # 1. Generate a random 6-digit token code
    verification_code = f"{random.randint(100000, 999999)}"
    
    # 2. Set expiration timestamp to 15 minutes from now
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    try:
        if server.db is None:
            return jsonify({"success": False, "message": "Database connection unavailable."}), 500
            
        # 3. Store code in Firestore under 'VerificationCodes'
        server.db.collection('VerificationCodes').document(email).set({
            'code': verification_code,
            'expires_at': expires_at,
            'verified': False
        })
            
        # 4. Compose and send the email
        msg = EmailMessage(
            subject="Your LiveAlert Verification Code",
            body=f"Your 6-digit verification code is: {verification_code}\n\nThis code will expire in 15 minutes.",
            to=[email]
        )
        msg.send()
        
        return jsonify({"success": True, "message": "Verification code sent to your email!"}), 200
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@auth_bp.route('/verify-code', methods=['POST'])
def verify_code():
    import server
    
    data = request.get_json() or {}
    email = data.get('email')
    user_code = data.get('code')
    
    if not email or not user_code:
        return jsonify({"success": False, "message": "Email and code are required."}), 400
        
    try:
        if server.db is None:
            return jsonify({"success": False, "message": "Database connection unavailable."}), 500
            
        # 1. Look up the code details in Firestore
        doc_ref = server.db.collection('VerificationCodes').document(email)
        doc = doc_ref.get()
        
        if not doc.exists:
            return jsonify({"success": False, "message": "No verification code found for this email."}), 400
            
        code_data = doc.to_dict()
        
        # 2. Check if code has already been claimed
        if code_data.get('verified'):
            return jsonify({"success": False, "message": "This code has already been used."}), 400
            
        # 3. Enforce the 15-minute expiration deadline
        expires_at = code_data.get('expires_at')
        if datetime.now(timezone.utc) > expires_at.replace(tzinfo=timezone.utc):
            return jsonify({"success": False, "message": "Verification code has expired."}), 400
            
        # 4. Confirm match strings
        if code_data.get('code') != str(user_code).strip():
            return jsonify({"success": False, "message": "Invalid verification code."}), 400
            
        # 5. Perfect match! Update tracking document
        doc_ref.update({'verified': True})
        
        return jsonify({"success": True, "message": "Email verified successfully!"}), 200
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500