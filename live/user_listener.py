from firebase_admin import messaging

def setup_active_calls_listener(db):
    """
    Sets up a real-time snapshot listener on the ActiveCalls collection.
    Runs continuously in the background to watch for status changes.
    """
    def callback(col_snapshot, changes, read_time):
        for change in changes:
            call_data = change.document.to_dict()
            call_id = change.document.id
            status = call_data.get('status', '').lower()
            notified = call_data.get('enRouteNotified', False)

            # Check if a document was newly added or modified
            if change.type.name in ['ADDED', 'MODIFIED']:
                # Check if status is en_route and hasn't already triggered a push
                if status == 'en_route' and not notified:
                    reporter_uuid = call_data.get('reporterUuid')
                    if not reporter_uuid:
                        continue

                    # Fetch the citizen's FCM token from the Users collection
                    user_doc = db.collection('Users').document(reporter_uuid).get()
                    if not user_doc.exists:
                        continue

                    citizen_token = user_doc.to_dict().get('fcmToken')
                    if not citizen_token:
                        continue

                    # Construct the proactive push message payload
                    message = messaging.Message(
                        token=citizen_token,
                        data={
                            "type": "RESPONDER_EN_ROUTE",
                            "callId": str(call_id),
                            "status": "en_route"
                        },
                        notification=messaging.Notification(
                            title="🚨 Responders Dispatched",
                            body="Emergency units are now en route to your location."
                        )
                    )

                    try:
                        # Send the push notification via Firebase Admin SDK
                        messaging.send(message)
                        
                        # Mark flag as True so it never sends duplicates
                        db.collection('ActiveCalls').document(call_id).update({
                            'enRouteNotified': True
                        })
                        print(f"🚀 Successfully sent 'En Route' push for call {call_id}")
                        
                    except Exception as e:
                        print(f"❌ Failed to send en-route push: {e}")

    # Attach the listener to your Firestore ActiveCalls collection
    db.collection('ActiveCalls').on_snapshot(callback)