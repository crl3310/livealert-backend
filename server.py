import os
from flask import Flask, jsonify
from flask_mailman import Mail
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv

# Load environmental workspace secrets from .env file
load_dotenv()


app = Flask(__name__)

# --- Email SMTP Configuration ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')


# Initialize Mail instance globally
mail = Mail(app)

# --- Firebase Initialization ---
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
import auth.verify
from live.live import live_bp 
from community.routes import community_bp
app.register_blueprint(community_bp, url_prefix='/api/community')
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(live_bp, url_prefix='/api/live')

@app.route('/', methods=['GET'])
def gateway_status():
    return jsonify({
        "status": "online",
        "message": "LiveAlert Main Gateway is active and linked to Firestore!"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)