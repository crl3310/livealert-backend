import os
import time
import tempfile
import json
from datetime import datetime, timezone
from flask import request, jsonify, Blueprint
from agora_token_builder import RtcTokenBuilder
from google import genai
from google.genai import types

# Relative imports from within the live package directory
from .schemas import EmergencyAnalysis
from .utils import get_readable_address, find_nearest_police_station

live_bp = Blueprint('live', __name__)
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

@live_bp.route('/get-token', methods=['POST'])
def get_token():
    import server
    data = request.get_json() or {}
    channel_name = data.get('channelName')
    reporter_uuid = data.get('uuid')  
    uid = data.get('uid', 0)          
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    if not channel_name or not reporter_uuid:
        return jsonify({"success": False, "message": "channelName and uuid are required."}), 400

    app_id = os.getenv('AGORA_APP_ID')
    app_certificate = os.getenv('AGORA_APP_CERTIFICATE')
    if not app_id or not app_certificate:
        return jsonify({"success": False, "message": "Agora credentials missing."}), 500

    privilege_expired_ts = int(time.time()) + 3600

    try:
        token = RtcTokenBuilder.buildTokenWithUid(app_id, app_certificate, channel_name, uid, 1, privilege_expired_ts)
        if server.db is None:
            return jsonify({"success": False, "message": "Database client uninitialized."}), 500

        call_payload = {
            'channelName': channel_name,
            'reporterUuid': reporter_uuid,  
            'status': 'evaluating',         
            'ai_assessment': 'Analyzing emergency video clip...',
            'timestamp': datetime.now(timezone.utc)
        }

        if latitude is not None and longitude is not None:
            lat_val, lon_val = float(latitude), float(longitude)
            readable_address = get_readable_address(lat_val, lon_val)
            call_payload['location'] = {
                'latitude': lat_val, 'longitude': lon_val,
                'address': readable_address or "Location found"
            }
            
            nearest_station = find_nearest_police_station(lat_val, lon_val)
            call_payload['assignedStation'] = nearest_station or {
                "stationName": "Unassigned - Outside Operational Radius",
                "dispatchStatus": "UNASSIGNED"
            }

        server.db.collection('ActiveCalls').document(channel_name).set(call_payload)
        return jsonify({"success": True, "token": token, "channelName": channel_name, "uid": uid}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@live_bp.route('/analyze-video', methods=['POST'])
def analyze_video():
    import server
    channel_name = request.form.get('channelName')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    
    if not channel_name or 'video' not in request.files:
        return jsonify({"success": False, "message": "Missing channelName or video file."}), 400

    video_file = request.files['video']
    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    temp_file_path = os.path.join(tempfile.gettempdir(), f"temp_{channel_name}.mp4")
    video_file.save(temp_file_path)

    try:
        gemini_file = client.files.upload(file=temp_file_path)
        while gemini_file.state.name == "PROCESSING":
            time.sleep(1)
            gemini_file = client.files.get(name=gemini_file.name)

        if gemini_file.state.name == "FAILED":
            raise Exception("Gemini video processing failed.")

        prompt = (
            "Analyze the following 10-15 second video and audio clip captured by a citizen. "
            "Examine both the video track for physical hazards and the audio track for sounds of distress "
            "(screams, crashes, gunfire, arguments). Classified incidents must align directly with the rubric "
            "provided in the response schema parameters."
        )
        
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=[gemini_file, prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=EmergencyAnalysis,
            ),
        )

        analysis_data = json.loads(response.text)
        update_payload = {
            'status': 'incoming',  
            'incidentType': analysis_data.get('incident_type'),
            'threatLevel': analysis_data.get('threat_level'),
            'ai_summary': analysis_data.get('summary'),
            'ai_reasoning': analysis_data.get('reasoning'),
            'analyzed_at': datetime.now(timezone.utc)
        }

        if latitude is not None and longitude is not None:
            readable_address = get_readable_address(latitude, longitude)
            update_payload['location'] = {
                'latitude': float(latitude), 'longitude': float(longitude),
                'address': readable_address or "Location found"
            }

        server.db.collection('ActiveCalls').document(channel_name).update(update_payload)
        client.files.delete(name=gemini_file.name)
        if os.path.exists(temp_file_path): os.remove(temp_file_path)

        return jsonify({"success": True, "message": "Emergency analyzed.", "assessment": analysis_data}), 200
    except Exception as e:
        if os.path.exists(temp_file_path): os.remove(temp_file_path)
        return jsonify({"success": False, "message": f"Analysis failed: {str(e)}"}), 500