import threading
from firebase_admin import messaging, firestore

def on_active_calls_snapshot(col_snapshot, changes, read_time):
    """
    Callback executed when ActiveCalls documents are created or modified.
    """
    for change in changes:
        # Check for newly added calls or modified unit assignments
        if change.type.name in ['ADDED', 'MODIFIED']:
            call_data = change.document.to_dict()
            call_id = change.document.id
            
            unit_id = call_data.get('unitId')
            station_id = call_data.get('stationId')
            dispatch_status = call_data.get('dispatchStatus')

            # Fire notification only if a unit is assigned and call is PENDING
            if unit_id and dispatch_status == 'PENDING':
                print(f"🚨 ALERT: Emergency '{call_id}' assigned to Station '{station_id}', Unit '{unit_id}'")
                send_push_to_unit(station_id, unit_id, call_id, call_data)

def send_push_to_unit(station_id, unit_id, call_id, call_data):
    """
    Queries on-duty responders belonging to unit_id and sends FCM push notifications.
    """
    import server
    if server.db is None:
        return

    try:
        # Query on-duty personnel matching stationId and unitId
        responders = server.db.collection('Responders') \
            .where('stationId', '==', station_id) \
            .where('unitId', '==', unit_id) \
            .where('duty', '==', 'on_duty') \
            .stream()

        fcm_tokens = []
        for doc in responders:
            data = doc.to_dict()
            token = data.get('fcmToken')  # Token registered during mobile login
            if token:
                fcm_tokens.append(token)

        if not fcm_tokens:
            print(f"ℹ️ No active FCM tokens found for on-duty responders in unit {unit_id}.")
            return

        # Prepare FCM multicast message
        message = messaging.MulticastMessage(
            tokens=fcm_tokens,
            data={
                "type": "NEW_ASSIGNMENT",
                "callId": str(call_id),
                "unitId": str(unit_id),
                "stationId": str(station_id)
            },
            notification=messaging.Notification(
                title="🚨 Emergency Call Assigned",
                body=f"Unit {unit_id} has been dispatched to a new call."
            )
        )

        response = messaging.send_each_for_multicast(message)
        print(f"📢 Notification successfully sent to {response.success_count} devices for unit {unit_id}.")

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