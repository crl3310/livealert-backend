import os
import tempfile
import json
import queue
from datetime import datetime, timezone
from flask import request, jsonify, Blueprint, Response
from google import genai
from google.genai import types

from .schemas import HazardImageAnalysis
from .utils import get_readable_address, find_nearest_police_station, calculate_distance_km

community_bp = Blueprint('community', __name__)
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Tracks active real-time stream connections with subscriber locations
# Format: [{"queue": Queue, "lat": float, "lon": float}, ...]
subscribers = []


def announce_new_hazard(hazard_data):
    """Broadcast hazard ONLY to active listeners within a 20 km radius."""
    hazard_lat = hazard_data.get('latitude')
    hazard_lon = hazard_data.get('longitude')

    for sub in list(subscribers):
        try:
            # Check distance if coordinates exist for both hazard and subscriber
            if hazard_lat is not None and hazard_lon is not None and sub['lat'] is not None and sub['lon'] is not None:
                dist = calculate_distance_km(hazard_lat, hazard_lon, sub['lat'], sub['lon'])
                
                # Only push event if subscriber is within 20 km!
                if dist <= 20.0:
                    sub['queue'].put_nowait(hazard_data)
            else:
                # Fallback: if coordinates are missing, broadcast by default
                sub['queue'].put_nowait(hazard_data)

        except Exception:
            subscribers.remove(sub)


@community_bp.route('/hazards/stream', methods=['GET'])
def stream_hazards():
    """Real-time SSE endpoint for connected app clients.
    Expects location parameters: /hazards/stream?lat=14.5026&lon=121.0430
    """
    user_lat = request.args.get('lat', type=float)
    user_lon = request.args.get('lon', type=float)

    def event_stream():
        q = queue.Queue()
        sub_record = {"queue": q, "lat": user_lat, "lon": user_lon}
        subscribers.append(sub_record)

        try:
            while True:
                data = q.get()  # Blocks until a report within 20km is announced
                yield f"data: {json.dumps(data)}\n\n"
        except GeneratorExit:
            if sub_record in subscribers:
                subscribers.remove(sub_record)

    return Response(event_stream(), content_type='text/event-stream')


@community_bp.route('/hazards/create', methods=['POST'])
def create_hazard():
    import server

    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    title = request.form.get('title')
    category = request.form.get('category', 'General')
    description = request.form.get('description', '')
    reporter_uuid = request.form.get('uuid')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')

    if not title or not reporter_uuid:
        return jsonify({"success": False, "message": "title and uuid are required."}), 400

    hazard_payload = {
        'title': title,
        'category': category,
        'description': description,
        'reporterUuid': reporter_uuid,
        'status': 'REPORTED',
        'timestamp': datetime.now(timezone.utc),
        'ai_assessment': None
    }

    lat_val = float(latitude) if latitude is not None else None
    lon_val = float(longitude) if longitude is not None else None

    # Location & Station Assignment
    if lat_val is not None and lon_val is not None:
        readable_address = get_readable_address(lat_val, lon_val)
        
        hazard_payload['location'] = {
            'latitude': lat_val,
            'longitude': lon_val,
            'address': readable_address or "Location recorded"
        }
        
        nearest_station = find_nearest_police_station(lat_val, lon_val)
        hazard_payload['assignedStation'] = nearest_station or {
            "stationName": "Unassigned - Outside Operational Radius",
            "dispatchStatus": "UNASSIGNED"
        }

    # Optional AI Image Assessment
    if 'image' in request.files and request.files['image'].filename != '':
        image_file = request.files['image']
        temp_file_path = os.path.join(tempfile.gettempdir(), f"hazard_{datetime.now().timestamp()}.jpg")
        image_file.save(temp_file_path)

        try:
            gemini_file = client.files.upload(file=temp_file_path)
            
            prompt = (
                "Analyze this community report image. Briefly describe the visual issue "
                "and provide a 1-sentence summary for the local community board."
            )

            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=[gemini_file, prompt],
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=HazardImageAnalysis,
                ),
            )

            hazard_payload['ai_assessment'] = json.loads(response.text)
            client.files.delete(name=gemini_file.name)
        except Exception as e:
            print(f"❌ Gemini AI Analysis Error: {e}")
        finally:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

    # Save to Firestore
    doc_ref = server.db.collection('Hazards').document()
    hazard_payload['hazardId'] = doc_ref.id
    doc_ref.set(hazard_payload)

    # Announce real-time alert to nearby subscribers within 20km
    announce_new_hazard({
        "id": doc_ref.id,
        "title": hazard_payload.get('title'),
        "category": hazard_payload.get('category'),
        "description": hazard_payload.get('description'),
        "locationName": hazard_payload.get('location', {}).get('address', 'Unknown Area'),
        "latitude": lat_val,
        "longitude": lon_val,
        "timestamp": datetime.now().strftime('%I:%M %p'),
        "assignedStation": hazard_payload.get('assignedStation'),
        "ai_assessment": hazard_payload.get('ai_assessment')
    })

    return jsonify({
        "success": True,
        "message": "Community report submitted successfully!",
        "hazardId": doc_ref.id,
        "assignedStation": hazard_payload.get('assignedStation'),
        "ai_assessment": hazard_payload.get('ai_assessment')
    }), 201


@community_bp.route('/hazards/list', methods=['GET'])
def get_hazards():
    import server

    if server.db is None:
        return jsonify({"success": False, "message": "Database client uninitialized."}), 500

    try:
        hazards_ref = server.db.collection('Hazards').stream()
        hazards_list = []

        for doc in hazards_ref:
            hazard_data = doc.to_dict()
            
            ts = hazard_data.get('timestamp')
            formatted_time = ts.strftime('%I:%M %p') if isinstance(ts, datetime) else "Just now"

            hazards_list.append({
                "id": doc.id,
                "title": hazard_data.get('title'),
                "category": hazard_data.get('category'),
                "status": hazard_data.get('status', 'REPORTED'),
                "locationName": hazard_data.get('location', {}).get('address', 'Unknown Area'),
                "time": formatted_time,
                "assignedStation": hazard_data.get('assignedStation'),
                "ai_assessment": hazard_data.get('ai_assessment')
            })

        return jsonify({
            "success": True,
            "hazards": hazards_list
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500