"""Chat between the reporter and the admin during a live call (for reporters who can't speak).

Messages live in Firestore, under the call:   ActiveCalls/{channelName}/Messages/{messageId}
    senderRole   'reporter' | 'admin'            (set by the SERVER from the login, never taken from the request)
    senderUid    uid of the sender
    text         up to 500 characters
    quickReply   key of a one-tap reply, or null
    createdAt    server timestamp
    pushedAt     set by the push listener (user_listener.py) once the reporter's phone was nudged

The reporter's app sends through this backend (POST /chat/send). The admin system writes its messages straight
into the same collection (same fields). Both sides see new messages in real time by listening to that collection;
this file also gives a catch-up endpoint for an app that missed messages (GET /chat/<channel>/messages).

Routes (attached to live_bp, so with your prefix they are /api/live/chat/...)
    POST /chat/send                       reporter   {channelName, text}  or  {channelName, quickReply}
    GET  /chat/<channel_name>/messages    reporter, or a responder with access to the call
                                          ?after=<messageId>  -> only messages after that one (oldest first)
                                          no `after`          -> the latest messages (for opening the screen)
"""
import logging

from flask import g, jsonify, request
from google.cloud import firestore

from app_core import get_db
from app_security import caller_can_view_call, error, require_auth, user_rate_limit, valid_channel
from .live import live_bp

log = logging.getLogger(__name__)

MAX_TEXT_LEN = 500
DEFAULT_PAGE = 50
MAX_PAGE = 100

# The chat stays open on 'cancelled_fake' on purpose: an admin may have marked a real emergency fake by mistake,
# and the reporter must still be able to say so. It becomes read-only once the call is truly over.
CLOSED_STATUSES = {'resolved', 'cancelled', 'rejected', 'fake'}

# One-tap replies for a reporter who can't type. The wording is fixed on the server.
QUICK_REPLIES = {
    'in_danger': "I'm in danger.",
    'cannot_talk': "I can't talk right now.",
    'send_police': "Please send police.",
    'need_medical': "I need medical help.",
}


def _clean_text(value):
    """Trimmed text without control characters (newlines and tabs are kept)."""
    return ''.join(ch for ch in value if ch >= ' ' or ch in '\n\t').strip()


def _iso(value):
    return value.isoformat() if hasattr(value, 'isoformat') else None


def _status(call):
    return str(call.get('status') or '').lower()


# ---------------------------------------------------------------------------
# Reporter sends a message
# ---------------------------------------------------------------------------
@live_bp.route('/chat/send', methods=['POST'])
@require_auth
@user_rate_limit('chat_send', 20, 60)
def chat_send():
    data = request.get_json(silent=True) or {}
    channel_name = data.get('channelName')
    quick = data.get('quickReply')

    if not valid_channel(channel_name):
        return error("Missing or invalid channelName.", 400)

    if quick is not None:
        quick = str(quick).strip().lower()
        if quick not in QUICK_REPLIES:
            return error(f"Invalid quickReply. Use one of: {', '.join(sorted(QUICK_REPLIES))}.", 400)
        text = QUICK_REPLIES[quick]
    else:
        raw = data.get('text')
        if not isinstance(raw, str):
            return error("text is required.", 400)
        text = _clean_text(raw)
        if not text:
            return error("The message can't be empty.", 400)
        if len(text) > MAX_TEXT_LEN:
            return error(f"The message is too long (max {MAX_TEXT_LEN} characters).", 400)

    try:
        db = get_db()
        call_ref = db.collection('ActiveCalls').document(channel_name)
        snap = call_ref.get()
        call = snap.to_dict() if snap.exists else None
        # Not your call = "not found", so channel names can't be probed.
        if not call or call.get('reporterUuid') != g.uid:
            return error("Emergency call record not found.", 404)
        if _status(call) in CLOSED_STATUSES:
            return error("This call is closed. The chat is read-only now.", 409, code="CALL_CLOSED")

        msg_ref = call_ref.collection('Messages').document()
        batch = db.batch()
        batch.set(msg_ref, {
            'senderRole': 'reporter',   # decided here, from the login: a client can't pose as the admin
            'senderUid': g.uid,
            'text': text,
            'quickReply': quick,
            'createdAt': firestore.SERVER_TIMESTAMP,
        })
        # Lets a dashboard show "new message" on its call list without listening to every chat.
        batch.update(call_ref, {'lastMessageAt': firestore.SERVER_TIMESTAMP, 'lastMessageRole': 'reporter'})
        batch.commit()

        return jsonify({"success": True, "messageId": msg_ref.id}), 201
    except Exception:
        log.exception("Failed to send chat message")
        return error("Could not send the message. Please try again.", 500)


# ---------------------------------------------------------------------------
# Catch-up / history
# ---------------------------------------------------------------------------
@live_bp.route('/chat/<channel_name>/messages', methods=['GET'])
@require_auth
@user_rate_limit('chat_read', 60, 60)
def chat_messages(channel_name):
    if not valid_channel(channel_name):
        return error("Emergency call record not found.", 404)

    try:
        call_ref = get_db().collection('ActiveCalls').document(channel_name)
        snap = call_ref.get()
        call = snap.to_dict() if snap.exists else None
        if not call or not caller_can_view_call(call):
            return error("Emergency call record not found.", 404)

        limit = request.args.get('limit', default=DEFAULT_PAGE, type=int)
        limit = max(1, min(limit if limit is not None else DEFAULT_PAGE, MAX_PAGE))

        messages = call_ref.collection('Messages')
        cursor = None
        after = (request.args.get('after') or '').strip()
        if after and '/' not in after:
            cursor_snap = messages.document(after).get()
            if cursor_snap.exists:
                cursor = cursor_snap

        if cursor is not None:
            docs = list(messages.order_by('createdAt').start_after(cursor).limit(limit).stream())
        else:
            docs = list(messages.order_by('createdAt', direction=firestore.Query.DESCENDING).limit(limit).stream())
            docs.reverse()

        items = []
        for doc in docs:
            m = doc.to_dict() or {}
            items.append({
                "id": doc.id,
                "senderRole": m.get('senderRole'),
                "text": m.get('text'),
                "quickReply": m.get('quickReply'),
                "createdAt": _iso(m.get('createdAt')),
            })

        return jsonify({
            "success": True,
            "messages": items,
            "count": len(items),
            "lastId": items[-1]["id"] if items else None,   # pass back as ?after= to get what comes next
            "chatOpen": _status(call) not in CLOSED_STATUSES,
        }), 200
    except Exception:
        log.exception("Failed to load chat messages")
        return error("Could not load the messages.", 500)