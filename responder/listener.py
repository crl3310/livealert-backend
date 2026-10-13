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
            
            # --- HANDLE CALL RESOLUTION / TERMINATION ---
            status = call_data.get('status', '').lower()
            # EXPANDED STATUS CHECK: Catch all variations of resolved/cancelled calls
            if status in ['resolved', 'cancelled', 'cancelled_fake', 'fake']:
                # Prevent looping if we already sent the termination notice
                if call_data.get('liveEndedNotified', False):
                    continue
                
                print(f"🛑 Call '{call_id}' status changed to '{status}'. Ending live session...")
                send_live_termination_push(call_id, call_data)
                continue

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

def send_push_to_units(station_id, unit_ids, call_id, call_data):
    """
    Queries responders by their 'unitId' field, then sends FCM push notifications.
    """
    import server
    if server.db is None:
        return

    try:
        fcm_tokens = []

        # Query responders where the 'unitId' field matches the assigned unit ID
        if unit_ids:
            for target_unit_id in unit_ids:
                query = server.db.collection('Responders') \
                    .where(filter=FieldFilter('unitId', '==', target_unit_id))
                
                responders = query.stream()
                for doc in responders:
                    doc_data = doc.to_dict()
                    if not station_id or doc_data.get('stationId') == station_id:
                        token = doc_data.get('fcmToken')
                        if token:
                            fcm_tokens.append(token)
                            print(f"✅ Found FCM token for unit '{target_unit_id}'")
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

def send_live_termination_push(call_id, call_data):
    """
    Gathers tokens for assigned units and citizen, then broadcasts an end-live push message.
    """
    import server
    if server.db is None:
        return

    try:
        fcm_tokens = []

        # 1. Gather responder tokens from assigned units
        assigned_station = call_data.get('assignedStation') or {}
        unit_ids = call_data.get('unitIds') or assigned_station.get('unitIds') or []
        if isinstance(unit_ids, str):
            unit_ids = [unit_ids]

        if unit_ids:
            for unit_id in unit_ids:
                query = server.db.collection('Responders') \
                    .where(filter=FieldFilter('unitId', '==', unit_id))
                for doc in query.stream():
                    token = doc.to_dict().get('fcmToken')
                    if token:
                        fcm_tokens.append(token)

        # 2. Gather citizen token using reporterUuid (Lookup in Users collection)
        reporter_uuid = call_data.get('reporterUuid')
        if reporter_uuid:
            user_doc = server.db.collection('Users').document(reporter_uuid).get()
            if user_doc.exists:
                citizen_token = user_doc.to_dict().get('fcmToken')
                if citizen_token:
                    fcm_tokens.append(citizen_token)
                    print(f"✅ Found citizen FCM token for reporter '{reporter_uuid}'")
                else:
                    print(f"⚠️ User document found for '{reporter_uuid}', but 'fcmToken' field is missing!")
            else:
                print(f"⚠️ User document '{reporter_uuid}' not found in Users collection.")

        if not fcm_tokens:
            print(f"ℹ️ No active FCM tokens found to terminate call '{call_id}'.")
            server.db.collection('ActiveCalls').document(call_id).update({'liveEndedNotified': True})
            return

        # Broadcast termination message to units and citizen simultaneously
        message = messaging.MulticastMessage(
            tokens=fcm_tokens,
            data={
                "type": "END_LIVE_SESSION",
                "callId": str(call_id),
                "status": str(call_data.get('status', 'resolved'))
            },
            notification=messaging.Notification(
                title="🔒 Emergency Call Resolved",
                body="The incident has been marked as resolved. Closing live session."
            )
        )

        response = messaging.send_each_for_multicast(message)
        print(f"🛑 Termination notice sent to {response.success_count} devices (Units + Citizen).")

        # Mark that the termination notification has been handled
        server.db.collection('ActiveCalls').document(call_id).update({'liveEndedNotified': True})

    except Exception as e:
        print(f"❌ Failed to send live termination push: {str(e)}")

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