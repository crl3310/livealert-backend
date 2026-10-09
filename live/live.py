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
        # 1. Upload video clip to Gemini API
        gemini_file = client.files.upload(file=temp_file_path)
        while gemini_file.state.name == "PROCESSING":
            time.sleep(1)
            gemini_file = client.files.get(name=gemini_file.name)

        if gemini_file.state.name == "FAILED":
            raise Exception("Gemini video processing failed.")

        # 2. Detailed prompt instructing Gemini on screen detection, audio inspection, and classification
        prompt = (
            "Analyze the following video and audio clip captured by a citizen in real-time.\n\n"
            "VISUAL INSPECTION:\n"
            "1. Check if the camera is recording a secondary screen (e.g., laptop display, mobile screen, TV, monitor, glare, moiré patterns, or bezels). "
            "If the footage is recorded off a screen, flag is_screen_recording as true and is_fake as true.\n"
            "2. Look for real, live physical hazards or incidents occurring in the physical environment.\n\n"
            "AUDIO INSPECTION:\n"
            "1. Listen closely to the audio track for real ambient sounds of distress (screams, arguments, crash impacts, gunshots, glass breaking, sirens).\n\n"
            "FLAGGING RULE:\n"
            "If the clip shows screen playback, a prank, staged acting, or no real active emergency visual/audio, "
            "flag is_fake as true and is_emergency as false."
        )
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=[gemini_file, prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=EmergencyAnalysis,
            ),
        )

        analysis_data = json.loads(response.text)

        # 3. Check if the report is fake, recorded off a screen, or non-emergency
        is_fake = (
            analysis_data.get('is_fake', False) 
            or not analysis_data.get('is_emergency', True)
            or analysis_data.get('is_screen_recording', False)
        )

        if is_fake:
            # HALT DISPATCH: Update Firestore status to rejected/fake
            update_payload = {
                'status': 'cancelled_fake',
                'incidentType': analysis_data.get('incident_type', 'Fake/Non-Emergency'),
                'threatLevel': 'NONE',
                'ai_summary': f"REJECTED: {analysis_data.get('summary', 'Fake, screen recording, or non-emergency report detected.')}",
                'analyzed_at': datetime.now(timezone.utc),
                'assignedStation.dispatchStatus': 'REJECTED'
            }
            
            server.db.collection('ActiveCalls').document(channel_name).update(update_payload)
            
            # Cleanup temp resources
            client.files.delete(name=gemini_file.name)
            if os.path.exists(temp_file_path): 
                os.remove(temp_file_path)

            return jsonify({
                "success": False, 
                "is_fake": True,
                "message": "Report rejected. AI detected fake content, screen playback, or non-emergency situation.",
                "assessment": analysis_data
            }), 200

        # 4. VALID EMERGENCY: Mark as 'incoming' to trigger dispatch
        update_payload = {
            'status': 'incoming',  
            'incidentType': analysis_data.get('incident_type', 'General Emergency'),
            'threatLevel': analysis_data.get('threat_level', 'MEDIUM'),
            'ai_summary': analysis_data.get('summary'),
            'analyzed_at': datetime.now(timezone.utc)
        }

        if latitude is not None and longitude is not None:
            readable_address = get_readable_address(latitude, longitude)
            update_payload['location'] = {
                'latitude': float(latitude), 'longitude': float(longitude),
                'address': readable_address or "Location found"
            }

        server.db.collection('ActiveCalls').document(channel_name).update(update_payload)
        
        # Cleanup temp resources
        client.files.delete(name=gemini_file.name)
        if os.path.exists(temp_file_path): 
            os.remove(temp_file_path)

        return jsonify({
            "success": True, 
            "is_fake": False,
            "message": "Emergency analyzed and dispatched successfully.", 
            "assessment": analysis_data
        }), 200

    except Exception as e:
        if os.path.exists(temp_file_path): 
            os.remove(temp_file_path)
        return jsonify({"success": False, "message": f"Analysis failed: {str(e)}"}), 500