import math
from geopy.geocoders import Nominatim


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


def find_nearest_police_station(user_lat, user_lon):
    """
    Finds the geographically closest station. Stations operate 24/7, so no
    duty/online check is applied. Stations without a Location are skipped.
    Returns None if no station with coordinates exists.
    """
    from app_core import get_db
    db = get_db()

    try:
        user_lat = float(user_lat)
        user_lon = float(user_lon)

        candidates = []

        for doc in db.collection('Stations').stream():
            station_data = doc.to_dict() or {}

            geopoint = station_data.get('Location') or station_data.get('location')
            if not geopoint:
                continue

            s_name = station_data.get('stationName') or station_data.get('station_name') or 'Unknown Station'

            s_commander = 'N/A'
            for key, val in station_data.items():
                if 'commander' in key.lower():
                    s_commander = val
                    break

            dist = calculate_distance(user_lat, user_lon, geopoint.latitude, geopoint.longitude)
            candidates.append({
                "stationId": doc.id,
                "stationName": s_name,
                "commanderName": s_commander,
                "distanceKm": dist,
                "dispatchStatus": "PENDING"
            })

        if not candidates:
            print("No stations with a valid Location found.")
            return None

        return min(candidates, key=lambda s: s["distanceKm"])
    except Exception as e:
        print(f"Error executing instant police routing calculation: {e}")
        return None