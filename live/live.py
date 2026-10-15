import os
import time
import tempfile
import json

from datetime import datetime, timezone
from flask import request, jsonify, Blueprint
from agora_token_builder import RtcTokenBuilder
from google import genai
from google.genai import types
from firebase_admin import storage

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
            
            if nearest_station and isinstance(call_payload['assignedStation'], dict):
                call_payload['assignedStation']['dispatchStatus'] = 'PENDING'

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
        # 1. Upload video clip to Gemini API for assessment
        gemini_file = client.files.upload(file=temp_file_path)
        while gemini_file.state.name == "PROCESSING":
            time.sleep(1)
            gemini_file = client.files.get(name=gemini_file.name)

        if gemini_file.state.name == "FAILED":
            raise Exception("Gemini video processing failed.")

        # Permissive prompt allowing screen recordings while evaluating emergency context
        prompt = (
            "Analyze the following video and audio clip captured in real-time. "
            "Note that the video may be recorded off a secondary screen (such as a laptop monitor, phone display, or television broadcast) showing an emergency or incident. "
            "Do NOT reject footage simply because it is displayed on a screen or monitor.\n\n"
            "VISUAL & AUDIO INSPECTION:\n"
            "1. Evaluate the content being displayed or recorded for any valid emergency, threat, or hazard (e.g., fire, accidents, crimes, medical distress, security issues).\n"
            "2. Listen to the audio track for any signs of distress, alarms, or emergency context.\n\n"
            "FLAGGING RULE:\n"
            "Only flag is_fake as true if the content is entirely non-emergency, a clear joke/prank, or completely irrelevant. "
            "If it depicts a real emergency scenario (even if shown via a screen or device), evaluate it as a valid emergency."
        )
        
        response = client.models.generate_content(
            model='gemini-3.8-flash',
            contents=[gemini_file, prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=EmergencyAnalysis,
            ),
        )

        analysis_data = json.loads(response.text)

        is_fake = (
            analysis_data.get('is_fake', False) 
            or not analysis_data.get('is_emergency', True)
        )

        if is_fake:
            update_payload = {
                'status': 'cancelled_fake',
                'incidentType': analysis_data.get('incident_type', 'Fake/Non-Emergency'),
                'threatLevel': 'NONE',
                'ai_assessment': f"REJECTED: {analysis_data.get('summary', 'Non-emergency report detected.')}",
                'analyzed_at': datetime.now(timezone.utc),
                'assignedStation.dispatchStatus': 'REJECTED'
            }
            server.db.collection('ActiveCalls').document(channel_name).update(update_payload)
            
            client.files.delete(name=gemini_file.name)
            if os.path.exists(temp_file_path): 
                os.remove(temp_file_path)

            return jsonify({
                "success": False, 
                "is_fake": True,
                "message": "Report rejected. AI detected a non-emergency situation.",
                "assessment": analysis_data
            }), 200

        # VALID EMERGENCY: Mark as 'incoming'
        update_payload = {
            'status': 'incoming',  
            'incidentType': analysis_data.get('incident_type', 'General Emergency'),
            'threatLevel': analysis_data.get('level') or analysis_data.get('threat_level', 'MEDIUM'),
            'ai_assessment': analysis_data.get('summary'),
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


@live_bp.route('/upload-evidence', methods=['POST'])
def upload_evidence():
    import server
    channel_name = request.form.get('channelName')
    reporter_uuid = request.form.get('reporterUuid')

    if not channel_name or not reporter_uuid or 'video' not in request.files:
        return jsonify({"success": False, "message": "Missing channelName, reporterUuid, or video file."}), 400

    video_file = request.files['video']
    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    # 1. Pre-check: Ensure the ActiveCall document exists and matches the reporter UUID
    call_ref = server.db.collection('ActiveCalls').document(channel_name)
    call_doc = call_ref.get()
    
    if not call_doc.exists:
        return jsonify({"success": False, "message": f"Active call '{channel_name}' not found."}), 404

    call_data = call_doc.to_dict() or {}
    stored_reporter_uuid = call_data.get('reporterUuid')

    if stored_reporter_uuid and stored_reporter_uuid != reporter_uuid:
        return jsonify({"success": False, "message": "Unauthorized: reporterUuid does not match this call."}), 403

    temp_file_path = os.path.join(tempfile.gettempdir(), f"evidence_{channel_name}.mp4")
    video_file.save(temp_file_path)

    blob = None
    try:
        bucket_name = os.getenv("FIREBASE_STORAGE_BUCKET")
        if not bucket_name:
            raise Exception("FIREBASE_STORAGE_BUCKET environment variable is missing.")

        bucket = storage.bucket(bucket_name)
        blob_path = f"evidence_videos/{channel_name}.mp4"
        blob = bucket.blob(blob_path)
        
        # Upload explicitly as video/mp4 for Android compatibility
        blob.upload_from_filename(temp_file_path, content_type='video/mp4')
        blob.make_public()
        evidence_url = blob.public_url

        # Save reference URL to the ActiveCalls document in Firestore
        call_ref.update({
            'evidenceUrl': evidence_url,
            'evidence_uploaded_at': datetime.now(timezone.utc)
        })

        # Cleanup local temp file
        if os.path.exists(temp_file_path): 
            os.remove(temp_file_path)

        return jsonify({
            "success": True,
            "message": "MP4 evidence video uploaded and linked successfully.",
            "evidenceUrl": evidence_url
        }), 200

    except Exception as e:
        # Cleanup local temp file
        if os.path.exists(temp_file_path): 
            os.remove(temp_file_path)
            
        # ROLLBACK: Delete the uploaded blob if an error occurred during the process
        if blob is not None:
            try:
                if blob.exists():
                    blob.delete()
                    print(f"🗑️ Rolled back: Deleted orphaned blob {blob.name} due to error.")
            except Exception as cleanup_err:
                print(f"⚠️ Failed to cleanup orphaned blob: {cleanup_err}")

        return jsonify({"success": False, "message": f"Evidence upload failed: {str(e)}"}), 500
        
from . import routes