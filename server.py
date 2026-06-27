from flask import Flask, jsonify
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

db = None
try:
    cred = credentials.Certificate("firebase-credentials.json")
    
    # Check if Firebase has already been initialized to prevent reloading crashes
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
        print("🚀 Firebase Admin SDK initialized successfully!")
    else:
        print("🔄 Firebase Admin SDK already running, skipping re-initialization.")
        
    db = firestore.client()
except Exception as e:
    print(f"❌ Failed to initialize Firebase: {e}")

# Register Blueprints (routes) from our sub-folders
from auth.register import auth_bp 
import auth.login 
app.register_blueprint(auth_bp, url_prefix='/api/auth')

@app.route('/', methods=['GET'])
def gateway_status():
    return jsonify({
        "status": "online",
        "message": "LiveAlert Main Gateway is active and linked to Firestore!"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)