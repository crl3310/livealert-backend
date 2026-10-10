import threading
import json
from firebase_admin import messaging, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

# Tracks initial startup load to prevent historical docs from triggering notifications
_initial_snapshot_complete = False

def on_active_calls_snapshot(col_snapshot, changes, read_time):
    """
    Callback executed when ActiveCalls documents are created or modified.
    """
    global _initial_snapshot_complete

    # Skip processing historical records on initial server startup
    if not _initial_snapshot_complete:
        _initial_snapshot_complete = True
        print(f"ℹ️ Listener initialized. Loaded {len(col_snapshot)} existing calls without triggering alerts.")
        return

    for change in changes:
        # Check for newly added calls or modified unit assignments
        if change.type.name in ['ADDED', 'MODIFIED']:
            call_data = change.document.to_dict()
            call_id = change.document.id
            
            # Prevent re-firing for calls that have already sent push notifications
            already_notified = call_data.get('notificationSent', False)
            if already_notified:
                continue

            # Safe extraction of nested assignedStation map object
            assigned_station = call_data.get('assignedStation') or {}
            
            # Extract unitIds (list) or fallback to single unitId (string)
            unit_ids = call_data.get('unitIds') or assigned_station.get('unitIds')
            single_unit = call_data.get('unitId') or assigned_station.get('unitId')

            # Normalize to a list of unit IDs
            if not unit_ids:
                unit_ids = [single_unit] if single_unit else []
            elif isinstance(unit_ids, str):
                unit_ids = [unit_ids]

            station_id = call_data.get('stationId') or assigned_station.get('stationId')
            dispatch_status = call_data.get('dispatchStatus') or assigned_station.get('dispatchStatus')

            # Fire notification only if call is PENDING and station is present
            if dispatch_status == 'PENDING':
                units_display = ", ".join(unit_ids) if unit_ids else "No units assigned yet"
                print(f"🚨 ALERT: Emergency '{call_id}' assigned to Station '{station_id}', Units: [{units_display}]")
                
                # Only send the push notification if units are actually assigned
                if unit_ids:
                    send_push_to_units(station_id, unit_ids, call_id, call_data)
                else:
                    print(f"ℹ️ Waiting for units to be assigned to '{call_id}'...")
                    # DO NOT mark notificationSent = True here, so future unit assignments can trigger it!

def send_push_to_units(station_id, unit_ids, call_id, call_data):
    """
    Fetches responders directly by document ID, then sends FCM push notifications.
    """
    import server
    if server.db is None:
        return

    try:
        fcm_tokens = []

        # If specific unit document IDs are provided, fetch them directly by ID
        if unit_ids:
            for uid in unit_ids:
                doc_ref = server.db.collection('Responders').document(uid).get()
                if doc_ref.exists:
                    doc_data = doc_ref.to_dict()
                    if not station_id or doc_data.get('stationId') == station_id:
                        token = doc_data.get('fcmToken')
                        if token:
                            fcm_tokens.append(token)
        else:
            # Fallback: query all on-duty responders for the station if no specific unit IDs
            query = server.db.collection('Responders') \
                .where(filter=FieldFilter('stationId', '==', station_id)) \
                .where(filter=FieldFilter('duty', '==', 'on_duty'))
            
            responders = query.stream()
            for doc in responders:
                data = doc.to_dict()
                token = data.get('fcmToken')
                if token:
                    fcm_tokens.append(token)

        if not fcm_tokens:
            print(f"ℹ️ No active FCM tokens found for units {unit_ids} in station {station_id}.")
            return

        # Prepare FCM multicast message
        units_str = ", ".join(unit_ids) if unit_ids else "Assigned Units"
        json_ids = json.dumps(unit_ids) if unit_ids else "[]"

        message = messaging.MulticastMessage(
            tokens=fcm_tokens,
            data={
                "type": "NEW_ASSIGNMENT",
                "callId": str(call_id),
                "unitIds": json_ids,
                "stationId": str(station_id or "")
            },
            notification=messaging.Notification(
                title="🚨 Emergency Call Assigned",
                body=f"Units [{units_str}] have been dispatched to a new call."
            )
        )

        response = messaging.send_each_for_multicast(message)
        print(f"📢 Notification successfully sent to {response.success_count} devices across assigned units.")

        # Mark document as notified in Firestore ONLY after successful notification
        server.db.collection('ActiveCalls').document(call_id).update({'notificationSent': True})

    except Exception as e:
        print(f"❌ Failed to send FCM push notification: {str(e)}")

def start_active_calls_listener():
    """
    Starts listening to ActiveCalls in a background thread without blocking Flask.
    """
    import server
    if server.db:
        try:
            calls_ref = server.db.collection('ActiveCalls')
            # Attach on_snapshot listener
            calls_ref.on_snapshot(on_active_calls_snapshot)
            print("📡 Real-time Firestore listener successfully initialized on 'ActiveCalls'.")
        except Exception as e:
            print(f"❌ Listener initialization failed: {str(e)}")