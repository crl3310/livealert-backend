import logging
from datetime import datetime, timedelta, timezone

from firebase_admin import messaging
from google.cloud.firestore_v1.base_query import FieldFilter

def setup_active_calls_listener(db):
    """
    Sets up a real-time snapshot listener on the ActiveCalls collection.
    Runs continuously in the background to watch for status changes.
    """
    def _callback(col_snapshot, changes, read_time):
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
    def callback(col_snapshot, changes, read_time):
        try:
            _callback(col_snapshot, changes, read_time)
        except Exception:
            logging.getLogger(__name__).exception('en-route listener failed')

    db.collection('ActiveCalls').on_snapshot(callback)


# ---------------------------------------------------------------------------
# CHAT: quiet push to the reporter when an admin/responder writes a message
# ---------------------------------------------------------------------------
CHAT_LOOKBACK = timedelta(minutes=2)  # after a restart, still push messages written just before it


def _push_chat_message(db, msg_ref):
    """Sends the reporter's phone a quiet, data-only push (nothing visible or audible, no message text) so the
    app fetches the new message. Marks the message `pushedAt` afterwards. Returns True if a push was sent."""
    call_ref = msg_ref.parent.parent
    if call_ref is None:
        return False
    call_doc = call_ref.get()
    if not call_doc.exists:
        return False
    reporter_uuid = (call_doc.to_dict() or {}).get('reporterUuid')
    if not reporter_uuid:
        return False

    user_doc = db.collection('Users').document(reporter_uuid).get()
    token = (user_doc.to_dict() or {}).get('fcmToken') if user_doc.exists else None
    if not token:
        return False

    messaging.send(messaging.Message(
        token=token,
        data={"type": "CHAT_MESSAGE", "callId": str(call_ref.id), "messageId": str(msg_ref.id)},
        # No `notification` block on purpose: the app decides how (and whether) to show anything.
        android=messaging.AndroidConfig(priority='high'),
        apns=messaging.APNSConfig(
            headers={'apns-priority': '5', 'apns-push-type': 'background'},
            payload=messaging.APNSPayload(aps=messaging.Aps(content_available=True)),
        ),
    ))
    msg_ref.update({'pushedAt': datetime.now(timezone.utc)})
    return True


def setup_chat_push_listener(db):
    """
    Watches every call's `Messages` subcollection. When someone other than the reporter (the admin) writes a message,
    the reporter's phone gets a quiet push. Messages already marked `pushedAt` are skipped, so a restart can't
    send duplicates.

    Needs ONE Firestore index (see CHAT notes): collection-group scope, collection ID `Messages`, field `createdAt`.
    If it is missing this logs the error (with the link that creates it) and the listener does not start.
    """
    log = logging.getLogger(__name__)
    since = datetime.now(timezone.utc) - CHAT_LOOKBACK
    query = db.collection_group('Messages').where(filter=FieldFilter('createdAt', '>=', since))

    try:
        list(query.limit(1).stream())  # fail loudly NOW if the index is missing, not silently later
    except Exception:
        log.exception("Chat push listener NOT started: the Firestore index for Messages.createdAt "
                      "(collection-group scope) is probably missing. Open the link in this error to create it.")
        return None

    def callback(col_snapshot, changes, read_time):
        for change in changes:
            if change.type.name != 'ADDED':
                continue
            try:
                msg = change.document.to_dict() or {}
                if msg.get('senderRole') == 'reporter' or msg.get('pushedAt'):
                    continue
                _push_chat_message(db, change.document.reference)
            except Exception:
                log.exception("Chat push failed for message %s", change.document.id)

    return query.on_snapshot(callback)