import math
from geopy.geocoders import Nominatim

# ---------------------------------------------------------------------------
# DUTY CONFIGURATION: adjust these to match your Firestore schema
# ---------------------------------------------------------------------------
RESPONDER_COLLECTION = 'Responders'    # collection holding station admins/responders
RESPONDER_STATION_FIELD = 'stationId'  # field linking a responder to a Stations doc id (e.g. "ST002")
RESPONDER_DUTY_FIELD = 'duty'          # field holding duty status ("on_duty" / "off_duty")
RESPONDER_ROLE_FIELD = 'role'          # field holding the account role

# Only these roles receive emergency calls
CALL_RECEIVING_ROLES = {'responder_admin', 'super_admin'}

# Values that mean "not working today". The online/offline presence field
# ("status") is ignored on purpose, so an offline admin does NOT disqualify
# a station. Only duty == off_duty does.
OFF_DUTY_VALUES = {'off_duty', 'off-duty', 'off duty', 'offduty'}


def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculates the great-circle distance between two GPS coordinates in kilometers."""
    R = 6371.0  # Earth's radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return round(R * c, 2)


def get_readable_address(latitude, longitude):
    """Converts latitude and longitude into a real, readable street address."""
    if latitude is None or longitude is None:
        return None
    try:
        geolocator = Nominatim(user_agent="guardian_eye_emergency_app")
        location = geolocator.reverse((float(latitude), float(longitude)), timeout=3)
        if location:
            return location.address
    except Exception as e:
        print(f"Reverse geocoding error: {e}")
    return None


def _is_off_duty(value):
    return str(value or '').strip().lower() in OFF_DUTY_VALUES


def get_stations_with_on_duty_responders():
    """
    Returns a set of station IDs (upper-cased) that have at least one responder
    who is not off duty. A station with 2 admins where 1 is off_duty/offline
    still qualifies as long as the other isn't off_duty.
    """
    import server
    available = set()
    if server.db is None:
        return available

    for doc in server.db.collection(RESPONDER_COLLECTION).stream():
        data = doc.to_dict() or {}
        role = str(data.get(RESPONDER_ROLE_FIELD) or '').strip().lower()
        if role not in CALL_RECEIVING_ROLES:
            continue
        station_id = data.get(RESPONDER_STATION_FIELD)
        if not station_id:
            continue
        if _is_off_duty(data.get(RESPONDER_DUTY_FIELD)):
            continue
        available.add(str(station_id).strip().upper())
    return available


def find_nearest_police_station(user_lat, user_lon):
    """
    Finds the geographically closest station that has at least one on-duty
    responder. Stations with nobody on duty are skipped, so the next nearest
    eligible station is chosen. Returns None if no station is available.
    """
    import server
    if server.db is None:
        return None

    try:
        user_lat = float(user_lat)
        user_lon = float(user_lon)

        on_duty_stations = get_stations_with_on_duty_responders()
        if not on_duty_stations:
            print("No stations currently have an on-duty responder.")
            return None

        candidates = []

        for doc in server.db.collection('Stations').stream():
            # Skip stations with no on-duty responder
            if doc.id.strip().upper() not in on_duty_stations:
                continue

            station_data = doc.to_dict() or {}

            s_name = station_data.get('stationName') or station_data.get('station_name') or 'Unknown Station'

            s_commander = 'N/A'
            for key, val in station_data.items():
                if 'commander' in key.lower():
                    s_commander = val
                    break

            geopoint = station_data.get('Location') or station_data.get('location')
            if not geopoint:
                continue

            dist = calculate_distance(user_lat, user_lon, geopoint.latitude, geopoint.longitude)
            candidates.append({
                "stationId": doc.id,
                "stationName": s_name,
                "commanderName": s_commander,
                "distanceKm": dist,
                "dispatchStatus": "PENDING"
            })

        if not candidates:
            return None

        return min(candidates, key=lambda s: s["distanceKm"])
    except Exception as e:
        print(f"Error executing instant police routing calculation: {e}")
        return None