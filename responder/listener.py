import threading
from firebase_admin import messaging, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

def on_active_calls_snapshot(col_snapshot, changes, read_time):
    """
    Callback executed when ActiveCalls documents are created or modified.
    """
    for change in changes:
        # Check for newly added calls or modified unit assignments
        if change.type.name in ['ADDED', 'MODIFIED']:
            call_data = change.document.to_dict()
            call_id = change.document.id
            
            # Safe extraction of nested assignedStation map object
            assigned_station = call_data.get('assignedStation') or {}
            
            # Check top-level fields or fallback to nested assignedStation values
            unit_id = call_data.get('unitId') or assigned_station.get('unitId')
            station_id = call_data.get('stationId') or assigned_station.get('stationId')
            dispatch_status = call_data.get('dispatchStatus') or assigned_station.get('dispatchStatus')

            # Fire notification only if call is PENDING and station is present
            if dispatch_status == 'PENDING':
                print(f"🚨 ALERT: Emergency '{call_id}' assigned to Station '{station_id}', Unit '{unit_id}'")
                send_push_to_unit(station_id, unit_id, call_id, call_data)

def send_push_to_unit(station_id, unit_id, call_id, call_data):
    """
    Queries on-duty responders belonging to stationId/unitId and sends FCM push notifications.
    """
    import server
    if server.db is None:
        return

    try:
        # Use .where(filter=FieldFilter(...)) instead of .filter(...)
        query = server.db.collection('Responders') \
            .where(filter=FieldFilter('stationId', '==', station_id)) \
            .where(filter=FieldFilter('duty', '==', 'on_duty'))

        # Add unit filter if unitId is defined on the call
        if unit_id:
            query = query.where(filter=FieldFilter('unitId', '==', unit_id))

        responders = query.stream()

        fcm_tokens = []
        for doc in responders:
            data = doc.to_dict()
            token = data.get('fcmToken')
            if token:
                fcm_tokens.append(token)

        if not fcm_tokens:
            print(f"ℹ️ No active FCM tokens found for on-duty responders in station {station_id} (unit {unit_id}).")
            return

        # Prepare FCM multicast message
        message = messaging.MulticastMessage(
            tokens=fcm_tokens,
            data={
                "type": "NEW_ASSIGNMENT",
                "callId": str(call_id),
                "unitId": str(unit_id or ""),
                "stationId": str(station_id or "")
            },
            notification=messaging.Notification(
                title="🚨 Emergency Call Assigned",
                body=f"Unit {unit_id or 'Assigned Unit'} has been dispatched to a new call."
            )
        )

        response = messaging.send_each_for_multicast(message)
        print(f"📢 Notification successfully sent to {response.success_count} devices.")

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
