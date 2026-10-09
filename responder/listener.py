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
                units_display = ", ".join(unit_ids) if unit_ids else "All Units"
                print(f"🚨 ALERT: Emergency '{call_id}' assigned to Station '{station_id}', Units: [{units_display}]")
                
                # Send the push notification
                send_push_to_units(station_id, unit_ids, call_id, call_data)

def send_push_to_units(station_id, unit_ids, call_id, call_data):
    """
    Queries on-duty responders belonging to stationId and matching any of the unitIds,
    then sends FCM push notifications.
    """
    import server
    if server.db is None:
        return

    try:
        # Base query: Station match and On Duty status
        query = server.db.collection('Responders') \
            .where(filter=FieldFilter('stationId', '==', station_id)) \
            .where(filter=FieldFilter('duty', '==', 'on_duty'))

        # Filter by unitIds using 'in' operator if provided
        if unit_ids:
            # Firestore 'in' query allows up to 30 items per batch
            query = query.where(filter=FieldFilter('unitId', 'in', unit_ids[:30]))

        responders = query.stream()

        fcm_tokens = []
        for doc in responders:
            data = doc.to_dict()
            token = data.get('fcmToken')
            if token:
                fcm_tokens.append(token)

        if not fcm_tokens:
            print(f"ℹ️ No active FCM tokens found for on-duty responders in station {station_id} for units {unit_ids}.")
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

        # Mark document as notified in Firestore so it won't trigger again
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