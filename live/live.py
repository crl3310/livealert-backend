import os
import time
import tempfile
import json
from datetime import datetime, timezone
from flask import request, jsonify, Blueprint
from agora_token_builder import RtcTokenBuilder

# --- Import for Reverse Geocoding ---
from geopy.geocoders import Nominatim

# --- Import the modern Google GenAI SDK and Pydantic for structured schema ---
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import Literal

# --- Define the Structured Output Schema ---
class EmergencyAnalysis(BaseModel):
    incident_type: str = Field(
        description="The classified category of the incident (e.g., Physical Assault, Car Accident, Fire Emergency, Medical Crisis, Suspicious Activity, Verbal Fight, Active Shooter, Unknown)."
    )
    threat_level: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        description="The priority classification. HIGH: Immediate threat to life, active violence, weapon drawn, fire, unconsciousness. MEDIUM: Escalating danger, non-life-threatening accidents, verbal fights. LOW: Non-violent, minor property damage, or false alarms."
    )
    summary: str = Field(
        description="A concise, objective 1-sentence summary of the visual and audio evidence observed in the clip."
    )
    reasoning: str = Field(
        description="A detailed 2-3 sentence technical justification of why this threat level and incident type were determined based on specific visual frames or sounds heard."
    )

live_bp = Blueprint('live', __name__)

# --- Initialize the modern Gemini Client ---
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# --- Helper function for Reverse Geocoding ---
def get_readable_address(latitude, longitude):
    """
    Converts latitude and longitude into a real, readable street address.
    Returns a string address or None if lookup fails.
    """
    if latitude is None or longitude is None:
        return None
        
    try:
        # User-agent is required by Nominatim's usage policy to prevent abuse
        geolocator = Nominatim(user_agent="guardian_eye_emergency_app")
        # Timeout safety of 3 seconds to avoid blocking your API routes
        location = geolocator.reverse((float(latitude), float(longitude)), timeout=3)
        if location:
            return location.address
    except Exception as e:
        print(f"Reverse geocoding error: {e}")
    return None


@live_bp.route('/get-token', methods=['POST'])
def get_token():
    import server  # Grab live Firestore database instance from server.py
    
    data = request.get_json() or {}
    channel_name = data.get('channelName')
    reporter_uuid = data.get('uuid')  # Changed from 'email' to 'uuid'
    uid = data.get('uid', 0)          # Clean 0 integer for Agora client routing
    
    # Capture optional location parameters from Android payload
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    # 1. Validation Check
    if not channel_name or not reporter_uuid:
        return jsonify({"success": False, "message": "channelName and uuid are required."}), 400

    app_id = os.getenv('AGORA_APP_ID')
    app_certificate = os.getenv('AGORA_APP_CERTIFICATE')

    if not app_id or not app_certificate:
        return jsonify({"success": False, "message": "Agora credentials missing in .env file."}), 500

    # 2. Token expiration configuration (Valid for 1 hour)
    expiration_time_in_seconds = 3600
    current_timestamp = int(time.time())
    privilege_expired_ts = current_timestamp + expiration_time_in_seconds

    try:
        # 3. Build the secure RTC token string using the integer UID
        token = RtcTokenBuilder.buildTokenWithUid(
            app_id, 
            app_certificate, 
            channel_name, 
            uid, 
            1, # Role 1 = Publisher/Broadcaster
            privilege_expired_ts
        )

        if server.db is None:
            return jsonify({"success": False, "message": "Database client uninitialized."}), 500

        # 4. Save call details
        call_payload = {
            'channelName': channel_name,
            'reporterUuid': reporter_uuid,  # Preserving your user system's string uuid
            'status': 'evaluating',         # Call is hidden from dispatchers during assessment
            'ai_assessment': 'Analyzing emergency video clip...',
            'timestamp': datetime.now(timezone.utc)
        }

        # If location exists, reverse-geocode to human-readable address and save
        if latitude is not None and longitude is not None:
            readable_address = get_readable_address(latitude, longitude)
            call_payload['location'] = {
                'latitude': float(latitude),
                'longitude': float(longitude),
                'address': readable_address or "Location found (Address translation pending)"
            }

        server.db.collection('ActiveCalls').document(channel_name).set(call_payload)

        # 5. Send information back to the Android client app
        return jsonify({
            "success": True,
            "token": token,
            "channelName": channel_name,
            "uid": uid
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@live_bp.route('/analyze-video', methods=['POST'])
def analyze_video():
    """
    Accepts a 10-15s MP4 video file from the Android app,
    uploads it to Gemini, analyzes video + audio using structured schema, and escalates the call.
    """
    import server

    # 1. Grab metadata from the form-data request
    channel_name = request.form.get('channelName')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    
    if not channel_name:
        return jsonify({"success": False, "message": "channelName is required."}), 400

    # 2. Extract the video file
    if 'video' not in request.files:
        return jsonify({"success": False, "message": "No video file provided."}), 400

    video_file = request.files['video']

    if video_file.filename == '':
        return jsonify({"success": False, "message": "No selected file."}), 400

    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    # 3. Save the video to a local temp file so the SDK can read/upload it
    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, f"temp_{channel_name}.mp4")
    video_file.save(temp_file_path)

    try:
        # 4. Upload the video using the modern File API
        print("Uploading video to Gemini API...")
        gemini_file = client.files.upload(file=temp_file_path)

        # Wait briefly for Gemini to process the video container in the cloud
        while gemini_file.state.name == "PROCESSING":
            time.sleep(1)
            gemini_file = client.files.get(name=gemini_file.name)

        if gemini_file.state.name == "FAILED":
            raise Exception("Gemini video processing failed.")

        # 5. Prompt Gemini with strict classification criteria
        prompt = (
            "Analyze the following 10-15 second video and audio clip captured by a citizen. "
            "Examine both the video track for physical hazards and the audio track for sounds of distress "
            "(screams, crashes, gunfire, arguments). Classified incidents must align directly with the rubric "
            "provided in the response schema parameters."
        )

        print("Analyzing video content with structured output schema...")
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=[gemini_file, prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=EmergencyAnalysis,
            ),
        )

        # Safely parse the strict JSON output directly into a python dict
        analysis_data = json.loads(response.text)

        # 6. Update document in Firestore with isolated, structured fields and optional location
        update_payload = {
            'status': 'incoming',  # Elevates call to live dashboard
            'incidentType': analysis_data.get('incident_type'),
            'threatLevel': analysis_data.get('threat_level'),
            'ai_summary': analysis_data.get('summary'),
            'ai_reasoning': analysis_data.get('reasoning'),
            'analyzed_at': datetime.now(timezone.utc)
        }

        # Save coordinates and human-readable address if provided
        if latitude is not None and longitude is not None:
            readable_address = get_readable_address(latitude, longitude)
            update_payload['location'] = {
                'latitude': float(latitude),
                'longitude': float(longitude),
                'address': readable_address or "Location found (Address translation pending)"
            }

        server.db.collection('ActiveCalls').document(channel_name).update(update_payload)

        # 7. Cleanup cloud file and local temp file
        client.files.delete(name=gemini_file.name)
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

        return jsonify({
            "success": True,
            "message": "Emergency analyzed and escalated.",
            "assessment": analysis_data
        }), 200

    except Exception as e:
        # Cleanup file if something goes wrong
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return jsonify({"success": False, "message": f"Analysis failed: {str(e)}"}), 500