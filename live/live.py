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

GEMINI_MODEL = 'gemini-3.8-flash'  # verify this model name is valid for your API key
GEMINI_PROCESSING_TIMEOUT_SEC = 60

DEFAULT_THREAT_LEVEL = 2  # used if the AI returns something unusable
NO_THREAT_LEVEL = 0       # used for rejected/fake reports


def normalize_threat_level(value, default=DEFAULT_THREAT_LEVEL):
    """Coerces the AI's threat level into an integer between 1 and 4."""
    try:
        level = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(4, level))


def make_temp_video_path():
    """Creates a unique temp .mp4 path (safe against odd characters in channel names)."""
    fd, path = tempfile.mkstemp(suffix='.mp4')
    os.close(fd)
    return path


@live_bp.route('/get-token', methods=['POST'])
def get_token():
    import server

    # Expecting form-data since a video clip is uploaded alongside token parameters
    channel_name = request.form.get('channelName')
    reporter_uuid = request.form.get('uuid')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')

    if not channel_name or not reporter_uuid:
        return jsonify({"success": False, "message": "channelName and uuid are required."}), 400

    if '/' in channel_name:
        return jsonify({"success": False, "message": "channelName must not contain '/'."}), 400

    try:
        uid = int(request.form.get('uid') or 0)
    except ValueError:
        return jsonify({"success": False, "message": "uid must be an integer."}), 400

    if 'video' not in request.files:
        return jsonify({"success": False, "message": "Initial verification video file is required before starting the live session."}), 400

    video_file = request.files['video']
    app_id = os.getenv('AGORA_APP_ID')
    app_certificate = os.getenv('AGORA_APP_CERTIFICATE')
    if not app_id or not app_certificate:
        return jsonify({"success": False, "message": "Agora credentials missing."}), 500

    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    temp_file_path = make_temp_video_path()
    video_file.save(temp_file_path)
    gemini_file = None

    try:
        # --- STEP 1: AI analysis MUST complete before issuing a token or going live ---
        gemini_file = client.files.upload(file=temp_file_path)
        deadline = time.time() + GEMINI_PROCESSING_TIMEOUT_SEC
        while gemini_file.state.name == "PROCESSING":
            if time.time() > deadline:
                raise Exception("Gemini video processing timed out.")
            time.sleep(1)
            gemini_file = client.files.get(name=gemini_file.name)

        if gemini_file.state.name == "FAILED":
            raise Exception("Gemini video processing failed.")

        # Active prompt (permissive toward screen playback)
        prompt = (
            "Analyze the following video and audio clip captured in real-time. "
            "Note that the video may be recorded off a secondary screen (such as a laptop monitor, phone display, or television broadcast) showing an emergency or incident. "
            "Do NOT reject footage simply because it is displayed on a screen or monitor.\n\n"
            "VISUAL & AUDIO INSPECTION:\n"
            "1. Evaluate the content being displayed or recorded for any valid emergency, threat, or hazard (e.g., fire, accidents, crimes, medical distress, security issues).\n"
            "2. Listen to the audio track for any signs of distress, alarms, or emergency context.\n\n"
            "THREAT LEVEL SCALE (integer):\n"
            "1 = low (minor, no immediate danger)\n"
            "2 = medium (potential danger or injury, needs prompt response)\n"
            "3 = high (immediate danger to life, urgent response needed)\n"
            "4 = critical (life-threatening, severe or rapidly escalating, multiple people at risk)\n\n"
            "FLAGGING RULE:\n"
            "Only flag is_fake as true if the content is entirely non-emergency, a clear joke/prank, or completely irrelevant. "
            "If it depicts a real emergency scenario (even if shown via a screen or device), evaluate it as a valid emergency."
        )

        # --- RESTRICTIVE PROMPT (use this to block screen recordings & faked scenarios) ---
        # If you switch to this, also revert the is_emergency / is_fake descriptions in schemas.py,
        # otherwise the schema will contradict the prompt.
        # prompt = (
        #     "Strictly analyze the following video and audio clip. "
        #     "You must detect if the footage is being recorded off a secondary screen, monitor, television, or digital display "
        #     "showing a pre-recorded video, movie, or simulated event rather than a genuine live-in-person emergency. "
        #     "If the video shows a screen recording, digital playback, mocked scenario, or non-authentic emergency context, "
        #     "you MUST flag is_fake as true and set is_emergency to false.\n\n"
        #     "THREAT LEVEL SCALE (integer): 1 = low, 2 = medium, 3 = high, 4 = critical."
        # )

        response = client.models.generate_content(
            model=GEMINI_MODEL,
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
            # Save record as cancelled/rejected without providing a stream token
            now = datetime.now(timezone.utc)
            call_payload = {
                'channelName': channel_name,
                'reporterUuid': reporter_uuid,
                'status': 'cancelled_fake',
                'incidentType': analysis_data.get('incident_type', 'Fake/Non-Emergency'),
                'threatLevel': NO_THREAT_LEVEL,
                'ai_assessment': f"REJECTED: {analysis_data.get('summary', 'Non-emergency report detected.')}",
                'timestamp': now,
                'analyzed_at': now
            }
            server.db.collection('ActiveCalls').document(channel_name).set(call_payload)

            return jsonify({
                "success": False,
                "is_fake": True,
                "message": "Report rejected. AI detected a non-emergency or simulated scenario.",
                "assessment": analysis_data
            }), 200

        # --- STEP 2: Valid emergency verified: generate token and set status to 'incoming' ---
        privilege_expired_ts = int(time.time()) + 3600
        token = RtcTokenBuilder.buildTokenWithUid(app_id, app_certificate, channel_name, uid, 1, privilege_expired_ts)

        threat_level = normalize_threat_level(analysis_data.get('threat_level'))
        analysis_data['threat_level'] = threat_level  # keep the returned assessment consistent

        now = datetime.now(timezone.utc)
        call_payload = {
            'channelName': channel_name,
            'reporterUuid': reporter_uuid,
            'status': 'incoming',
            'incidentType': analysis_data.get('incident_type', 'General Emergency'),
            'threatLevel': threat_level,
            'ai_assessment': analysis_data.get('summary'),
            'timestamp': now,
            'analyzed_at': now
        }

        unassigned_station = {
            "stationName": "Unassigned - No On-Duty Station Available",
            "dispatchStatus": "UNASSIGNED"
        }

        if latitude is not None and longitude is not None:
            lat_val, lon_val = float(latitude), float(longitude)
            readable_address = get_readable_address(lat_val, lon_val)
            call_payload['location'] = {
                'latitude': lat_val, 'longitude': lon_val,
                'address': readable_address or "Location found"
            }

            nearest_station = find_nearest_police_station(lat_val, lon_val)
            call_payload['assignedStation'] = nearest_station or unassigned_station
        else:
            # No GPS provided: still record the call as unassigned so it isn't silently orphaned
            call_payload['assignedStation'] = unassigned_station

        server.db.collection('ActiveCalls').document(channel_name).set(call_payload)

        return jsonify({
            "success": True,
            "is_fake": False,
            "token": token,
            "channelName": channel_name,
            "uid": uid,
            "message": "Emergency pre-analyzed and verified successfully.",
            "assessment": analysis_data
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Pre-analysis or token generation failed: {str(e)}"}), 500

    finally:
        # Runs on every path (success, fake, error): no leaked temp files or Gemini uploads
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        if gemini_file is not None:
            try:
                client.files.delete(name=gemini_file.name)
            except Exception as cleanup_err:
                print(f"⚠️ Failed to delete Gemini file: {cleanup_err}")


@live_bp.route('/upload-evidence', methods=['POST'])
def upload_evidence():
    import server
    channel_name = request.form.get('channelName')
    reporter_uuid = request.form.get('reporterUuid')

    if not channel_name or not reporter_uuid or 'video' not in request.files:
        return jsonify({"success": False, "message": "Missing channelName, reporterUuid, or video file."}), 400

    if '/' in channel_name:
        return jsonify({"success": False, "message": "channelName must not contain '/'."}), 400

    video_file = request.files['video']
    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    call_ref = server.db.collection('ActiveCalls').document(channel_name)
    call_doc = call_ref.get()

    if not call_doc.exists:
        return jsonify({"success": False, "message": f"Active call '{channel_name}' not found."}), 404

    call_data = call_doc.to_dict() or {}
    stored_reporter_uuid = call_data.get('reporterUuid')

    if stored_reporter_uuid and stored_reporter_uuid != reporter_uuid:
        return jsonify({"success": False, "message": "Unauthorized: reporterUuid does not match this call."}), 403

    temp_file_path = make_temp_video_path()
    video_file.save(temp_file_path)

    blob = None
    try:
        bucket_name = os.getenv("FIREBASE_STORAGE_BUCKET")
        if not bucket_name:
            raise Exception("FIREBASE_STORAGE_BUCKET environment variable is missing.")

        bucket = storage.bucket(bucket_name)
        blob_path = f"evidence_videos/{channel_name}.mp4"
        blob = bucket.blob(blob_path)

        blob.upload_from_filename(temp_file_path, content_type='video/mp4')
        blob.make_public()
        evidence_url = blob.public_url

        call_ref.update({
            'evidenceUrl': evidence_url,
            'evidence_uploaded_at': datetime.now(timezone.utc)
        })

        return jsonify({
            "success": True,
            "message": "MP4 evidence video uploaded and linked successfully.",
            "evidenceUrl": evidence_url
        }), 200

    except Exception as e:
        # ROLLBACK: delete the uploaded blob if an error occurred during the process
        if blob is not None:
            try:
                if blob.exists():
                    blob.delete()
                    print(f"🗑️ Rolled back: Deleted orphaned blob {blob.name} due to error.")
            except Exception as cleanup_err:
                print(f"⚠️ Failed to cleanup orphaned blob: {cleanup_err}")

        return jsonify({"success": False, "message": f"Evidence upload failed: {str(e)}"}), 500

    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


from . import routes