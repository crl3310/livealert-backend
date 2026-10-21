import json
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from agora_token_builder import RtcTokenBuilder
from flask import Blueprint, g, jsonify, request
from google import genai
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
from google.genai import types

from app_core import get_bucket, get_db, signed_url
from app_security import as_aware_utc, error, parse_coords, require_auth, user_rate_limit, valid_channel
from .ai_mode import get_analysis_config, resolve_mode  # DEMO-MODE
from .utils import find_nearest_police_station, get_readable_address

log = logging.getLogger(__name__)

live_bp = Blueprint('live', __name__)
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")  # verify this model name is valid for your API key
GEMINI_PROCESSING_TIMEOUT_SEC = 60

AI_MAX_ATTEMPTS = int(os.getenv("AI_MAX_ATTEMPTS", "2"))  # retries are cheap now that nobody is waiting on them
AI_WORKERS = int(os.getenv("AI_WORKERS", "6"))            # max simultaneous Gemini analyses
CLIP_GRACE_SEC = int(os.getenv("CLIP_GRACE_SEC", "120"))  # live call with no verification clip after this long -> manual review

DEFAULT_THREAT_LEVEL = 2  # provisional level shown until the AI replies (also used if the AI returns junk)
NO_THREAT_LEVEL = 0       # used for rejected/fake reports

# Written to the existing fields while the AI is still working. A call with no analyzed_at yet is still pending.
PENDING_INCIDENT_TYPE = "Pending AI Analysis"
PENDING_ASSESSMENT = "AI analysis in progress."
FAILED_ASSESSMENT = "Automatic AI analysis was unavailable; this report needs manual review."
NO_CLIP_ASSESSMENT = "No verification clip was received; this report needs manual review."

# Background pool: caps concurrent Gemini calls and keeps them off the gunicorn request threads.
_executor = ThreadPoolExecutor(max_workers=AI_WORKERS, thread_name_prefix="ai-analysis")


def normalize_threat_level(value, default=DEFAULT_THREAT_LEVEL):
    """Coerces the AI's threat level into an integer between 1 and 4."""
    try:
        level = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(4, level))


def make_temp_video_path():
    fd, path = tempfile.mkstemp(suffix='.mp4')
    os.close(fd)
    return path


def _remove_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        log.warning("Could not delete temp file %s", path)


# Prompt + response schema now come from ai_mode.py (switchable permissive/restrictive).


def analyze_video(video_path, mode):
    """Uploads the clip to Gemini, returns the parsed analysis dict. Always cleans up the Gemini file."""
    gemini_file = None
    try:
        gemini_file = client.files.upload(file=video_path)
        deadline = time.time() + GEMINI_PROCESSING_TIMEOUT_SEC
        while gemini_file.state.name == "PROCESSING":
            if time.time() > deadline:
                raise TimeoutError("Gemini video processing timed out.")
            time.sleep(1)
            gemini_file = client.files.get(name=gemini_file.name)
        if gemini_file.state.name == "FAILED":
            raise RuntimeError("Gemini video processing failed.")

        prompt, schema = get_analysis_config(mode)  # DEMO-MODE
        log.info("Analysing clip in %s mode", mode)
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=[gemini_file, prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )
        return json.loads(response.text)
    finally:
        if gemini_file is not None:
            try:
                client.files.delete(name=gemini_file.name)
            except Exception:
                log.warning("Failed to delete Gemini file")


# ---------------------------------------------------------------------------
# Background work. Nothing below may touch flask's request / g: it runs on pool threads,
# so everything it needs is passed in as plain arguments.
# ---------------------------------------------------------------------------
def _update_if_current(call_ref, call_ts, fields):
    """Applies fields to the call only if it is still the same call (same creation timestamp).
    If the reporter restarted the same channel in the meantime, a late result must not touch the new call."""

    @firestore.transactional
    def _txn(txn):
        snap = call_ref.get(transaction=txn)
        if not snap.exists or (snap.to_dict() or {}).get('timestamp') != call_ts:
            return False
        txn.update(call_ref, fields)
        return True

    return _txn(get_db().transaction())


def _mark_ai_failed(call_ref, call_ts):
    """The call stays live and visible; it is just flagged so a human reviews it."""
    try:
        _update_if_current(call_ref, call_ts, {
            'aiUnavailable': True,
            'ai_assessment': FAILED_ASSESSMENT,
            'analyzed_at': datetime.now(timezone.utc),
        })
    except Exception:
        log.exception("Could not record AI failure")


def _apply_analysis(call_ref, call_ts, analysis):
    """Writes the AI verdict onto the call and returns a short outcome string for logging.

    - real emergency            -> update threat level / type / summary, status untouched
    - fake, call still 'incoming' -> status 'cancelled_fake' (listener.py then pushes END_LIVE_SESSION)
    - fake, responders engaged  -> status untouched, flagged in ai_assessment for a human decision.
                                   A late AI verdict must never override responders who already acted.
    """
    is_fake = bool(analysis.get('is_fake', False)) or not analysis.get('is_emergency', True)
    summary = analysis.get('summary')
    incident_type = analysis.get('incident_type')
    now = datetime.now(timezone.utc)

    @firestore.transactional
    def _txn(txn):
        snap = call_ref.get(transaction=txn)
        if not snap.exists:
            return 'call_gone'
        call = snap.to_dict() or {}
        if call.get('timestamp') != call_ts:
            return 'superseded'

        status = str(call.get('status') or '').lower()
        update = {'analyzed_at': now, 'aiUnavailable': False}

        if not is_fake:
            update.update({
                'incidentType': incident_type or 'General Emergency',
                'threatLevel': normalize_threat_level(analysis.get('threat_level')),
                'ai_assessment': summary,
                'aiScreenRecording': bool(analysis.get('is_screen_recording', False)),
            })
            outcome = 'verified'
        elif status == 'incoming':
            update.update({
                'status': 'cancelled_fake',
                'incidentType': incident_type or 'Fake/Non-Emergency',
                'threatLevel': NO_THREAT_LEVEL,
                'ai_assessment': f"REJECTED: {summary or 'Non-emergency report detected.'}",
            })
            outcome = 'cancelled_fake'
        else:
            update.update({
                'ai_assessment': f"FLAGGED AS LIKELY FAKE (responders already engaged): "
                                 f"{summary or 'Non-emergency report detected.'}",
            })
            outcome = 'flagged_fake'

        txn.update(call_ref, update)
        return outcome

    return _txn(get_db().transaction())


def _run_analysis(channel_name, call_ts, video_path, mode):
    """Pool task: analyse the clip, write the verdict, always delete the temp file."""
    call_ref = get_db().collection('ActiveCalls').document(channel_name)
    try:
        analysis = None
        for attempt in range(1, AI_MAX_ATTEMPTS + 1):
            try:
                analysis = analyze_video(video_path, mode)
                break
            except Exception:
                log.exception("AI analysis attempt %d/%d failed for %s", attempt, AI_MAX_ATTEMPTS, channel_name)
                if attempt < AI_MAX_ATTEMPTS:
                    time.sleep(2)

        if analysis is None:
            _mark_ai_failed(call_ref, call_ts)
            return

        outcome = _apply_analysis(call_ref, call_ts, analysis)
        log.info("AI analysis for %s finished: %s", channel_name, outcome)
    except Exception:
        log.exception("Background analysis crashed for %s", channel_name)
        _mark_ai_failed(call_ref, call_ts)
    finally:
        _remove_file(video_path)


def _fill_address(channel_name, call_ts, lat, lon):
    """Pool task: reverse geocoding can take seconds, so it no longer blocks the report."""
    try:
        address = get_readable_address(lat, lon)
        if not address:
            return
        call_ref = get_db().collection('ActiveCalls').document(channel_name)
        _update_if_current(call_ref, call_ts, {'location.address': address})
    except Exception:
        log.exception("Address lookup failed for %s", channel_name)


def _claim_clip_slot(call_ref, call_ts):
    """Atomically records that this call's verification clip arrived. False if a clip was already submitted
    or the call was replaced/removed in the meantime (so a double upload can't start two analyses)."""

    @firestore.transactional
    def _txn(txn):
        snap = call_ref.get(transaction=txn)
        if not snap.exists:
            return False
        call = snap.to_dict() or {}
        if call.get('timestamp') != call_ts or call.get('aiClipSubmittedAt'):
            return False
        txn.update(call_ref, {'aiClipSubmittedAt': datetime.now(timezone.utc)})
        return True

    return _txn(get_db().transaction())


def _flag_if_no_clip(channel_name, call_ts):
    """Timer task for 'stream first, clip later': if no clip ever arrived, the call stays live but is flagged
    for manual review, so skipping verification can't be used to dodge the AI check."""
    try:
        call_ref = get_db().collection('ActiveCalls').document(channel_name)
        now = datetime.now(timezone.utc)

        @firestore.transactional
        def _txn(txn):
            snap = call_ref.get(transaction=txn)
            if not snap.exists:
                return
            call = snap.to_dict() or {}
            if call.get('timestamp') != call_ts or call.get('aiClipSubmittedAt') or call.get('analyzed_at'):
                return
            txn.update(call_ref, {'aiUnavailable': True, 'ai_assessment': NO_CLIP_ASSESSMENT, 'analyzed_at': now})

        _txn(get_db().transaction())
    except Exception:
        log.exception("No-clip check failed for %s", channel_name)


def recover_stuck_analyses(max_age=timedelta(minutes=5)):
    """Call once at boot. A restart kills in-flight analyses (their temp clips are gone), which would leave
    calls looking 'pending' forever. Calls still 'incoming' with no analyzed_at after max_age are flagged
    for manual review."""
    try:
        cutoff = datetime.now(timezone.utc) - max_age
        count = 0
        for doc in get_db().collection('ActiveCalls').where(filter=FieldFilter('status', '==', 'incoming')).stream():
            call = doc.to_dict() or {}
            if call.get('analyzed_at'):
                continue
            created = call.get('timestamp')
            if created and as_aware_utc(created) > cutoff:
                continue  # young enough that it may still be running
            doc.reference.update({
                'aiUnavailable': True,
                'ai_assessment': FAILED_ASSESSMENT,
                'analyzed_at': datetime.now(timezone.utc),
            })
            count += 1
        if count:
            log.warning("Marked %d interrupted AI analyses for manual review", count)
    except Exception:
        log.exception("Could not recover stuck analyses")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@live_bp.route('/get-token', methods=['POST'])
@require_auth
@user_rate_limit('get-token', 20, 3600)
def get_token():
    channel_name = request.form.get('channelName')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')

    # The reporter is whoever is signed in. A client-supplied uuid can't impersonate someone else.
    reporter_uuid = g.uid
    ai_mode = resolve_mode(request.form.get('aiMode'))  # DEMO-MODE: ignored unless ENABLE_DEMO_AI_MODE=1
    if request.form.get('uuid') and request.form.get('uuid') != g.uid:
        return error("uuid does not match the signed-in account.", 403)

    if not channel_name:
        return error("channelName is required.", 400)
    if not valid_channel(channel_name):
        return error("channelName may only contain letters, digits and _ - : . @ + = (max 64 chars).", 400)

    try:
        uid = int(request.form.get('uid') or 0)
    except ValueError:
        return error("uid must be an integer.", 400)
    if not 0 <= uid < 2 ** 32:
        return error("uid out of range.", 400)

    lat_val = lon_val = None
    if latitude is not None and longitude is not None:
        try:
            lat_val, lon_val = parse_coords(latitude, longitude)
        except ValueError:
            return error("Invalid latitude/longitude.", 400)

    # The clip is optional here: the app can go live first and send it afterwards to /verify-clip.
    has_clip = 'video' in request.files

    app_id = os.getenv('AGORA_APP_ID')
    app_certificate = os.getenv('AGORA_APP_CERTIFICATE')
    if not app_id or not app_certificate:
        log.error("Agora credentials missing")
        return error("Service configuration error.", 500)

    db = get_db()

    # A channel name can't be hijacked: if the call already exists it must be the caller's own.
    call_ref = db.collection('ActiveCalls').document(channel_name)
    existing = call_ref.get()
    if existing.exists and (existing.to_dict() or {}).get('reporterUuid') != reporter_uuid:
        return error("This channel name is already in use.", 409)

    temp_file_path = make_temp_video_path() if has_clip else None
    handed_off = False  # once the background task owns the temp file, it is the one that deletes it
    try:
        if has_clip:
            request.files['video'].save(temp_file_path)
            if os.path.getsize(temp_file_path) == 0:
                return error("The video file is empty.", 400)

        # --- Go live immediately: token + call record with provisional values ---
        privilege_expired_ts = int(time.time()) + 3600
        token = RtcTokenBuilder.buildTokenWithUid(app_id, app_certificate, channel_name, uid, 1, privilege_expired_ts)

        now = datetime.now(timezone.utc)  # doubles as the call's identity for the background tasks
        call_payload = {
            'channelName': channel_name,
            'reporterUuid': reporter_uuid,
            'status': 'incoming',
            'incidentType': PENDING_INCIDENT_TYPE,
            'threatLevel': DEFAULT_THREAT_LEVEL,
            'ai_assessment': PENDING_ASSESSMENT,
            'timestamp': now,
            'aiMode': ai_mode,  # DEMO-MODE
        }
        if has_clip:
            call_payload['aiClipSubmittedAt'] = now

        unassigned_station = {
            "stationName": "Unassigned - No On-Duty Station Available",
            "dispatchStatus": "UNASSIGNED"
        }

        if lat_val is not None:
            # Address starts as the old fallback text; _fill_address swaps in the real one a moment later.
            call_payload['location'] = {'latitude': lat_val, 'longitude': lon_val, 'address': "Location found"}
            call_payload['assignedStation'] = find_nearest_police_station(lat_val, lon_val) or unassigned_station
        else:
            call_payload['assignedStation'] = unassigned_station

        call_ref.set(call_payload)

        # --- Everything slow happens after this point, off the request ---
        if has_clip:
            try:
                _executor.submit(_run_analysis, channel_name, now, temp_file_path, ai_mode)
                handed_off = True
            except Exception:
                log.exception("Could not queue AI analysis")
                _mark_ai_failed(call_ref, now)
        else:
            timer = threading.Timer(CLIP_GRACE_SEC, _flag_if_no_clip, args=(channel_name, now))
            timer.daemon = True
            timer.start()

        if lat_val is not None:
            try:
                _executor.submit(_fill_address, channel_name, now, lat_val, lon_val)
            except Exception:
                log.exception("Could not queue address lookup")

        return jsonify({
            "success": True,
            "is_fake": False,
            "token": token,
            "channelName": channel_name,
            "uid": uid,
            "aiMode": ai_mode,  # DEMO-MODE: lets the app show which mode is active
            "message": ("Live session started. AI verification is running in the background." if has_clip
                        else "Live session started. Send the verification clip to /verify-clip."),
            "clipExpected": not has_clip,  # True = the app should now record and POST the clip to /verify-clip
            # Same shape the client used to receive, filled with provisional values.
            "assessment": {
                "pending": True,
                "threat_level": DEFAULT_THREAT_LEVEL,
                "incident_type": PENDING_INCIDENT_TYPE,
                "summary": PENDING_ASSESSMENT,
            }
        }), 200

    except Exception:
        log.exception("Token generation failed")
        return error("Could not start the live session. Please try again.", 500)

    finally:
        if temp_file_path and not handed_off:
            _remove_file(temp_file_path)


@live_bp.route('/verify-clip', methods=['POST'])
@require_auth
@user_rate_limit('verify-clip', 20, 3600)
def verify_clip():
    """Second half of 'stream first, verify in parallel': the app is already live and sends the short
    verification clip as soon as it has recorded it. Analysis then runs in the background as usual."""
    channel_name = request.form.get('channelName')
    if not channel_name or 'video' not in request.files:
        return error("Missing channelName or video file.", 400)
    if not valid_channel(channel_name):
        return error("Invalid channelName.", 400)

    call_ref = get_db().collection('ActiveCalls').document(channel_name)
    snap = call_ref.get()
    if not snap.exists:
        return error(f"Active call '{channel_name}' not found.", 404)
    call = snap.to_dict() or {}
    if call.get('reporterUuid') != g.uid:
        return error("Unauthorized: this call does not belong to you.", 403)
    if str(call.get('status') or '').lower() == 'cancelled_fake':
        return error("This report was already rejected.", 403)
    call_ts = call.get('timestamp')

    # DEMO-MODE: reuse the mode chosen at /get-token unless the app sends aiMode again.
    ai_mode = resolve_mode(request.form.get('aiMode') or call.get('aiMode'))

    temp_file_path = make_temp_video_path()
    handed_off = False
    try:
        request.files['video'].save(temp_file_path)
        if os.path.getsize(temp_file_path) == 0:
            return error("The video file is empty.", 400)
        if not _claim_clip_slot(call_ref, call_ts):
            return error("A verification clip was already submitted for this call.", 409)

        try:
            _executor.submit(_run_analysis, channel_name, call_ts, temp_file_path, ai_mode)
            handed_off = True
        except Exception:
            log.exception("Could not queue AI analysis")
            _mark_ai_failed(call_ref, call_ts)

        return jsonify({
            "success": True,
            "aiMode": ai_mode,  # DEMO-MODE
            "message": "Verification clip received. AI verification is running in the background.",
        }), 200
    except Exception:
        log.exception("Verification clip failed")
        return error("Could not process the verification clip. Please try again.", 500)
    finally:
        if not handed_off:
            _remove_file(temp_file_path)


@live_bp.route('/upload-evidence', methods=['POST'])
@require_auth
@user_rate_limit('upload-evidence', 30, 3600)
def upload_evidence():
    channel_name = request.form.get('channelName')

    if not channel_name or 'video' not in request.files:
        return error("Missing channelName or video file.", 400)
    if not valid_channel(channel_name):
        return error("Invalid channelName.", 400)
    # The caller must own the call. (reporterUuid in the body used to be trusted, and optional.)
    if request.form.get('reporterUuid') and request.form.get('reporterUuid') != g.uid:
        return error("reporterUuid does not match the signed-in account.", 403)

    call_ref = get_db().collection('ActiveCalls').document(channel_name)
    call_doc = call_ref.get()
    if not call_doc.exists:
        return error(f"Active call '{channel_name}' not found.", 404)

    call_data = call_doc.to_dict() or {}
    if call_data.get('reporterUuid') != g.uid:
        return error("Unauthorized: this call does not belong to you.", 403)
    if call_data.get('status') == 'cancelled_fake':
        return error("Evidence can't be attached to a rejected report.", 403)

    temp_file_path = make_temp_video_path()
    request.files['video'].save(temp_file_path)

    blob = None
    try:
        if os.path.getsize(temp_file_path) == 0:
            return error("The video file is empty.", 400)

        blob_path = f"evidence_videos/{channel_name}.mp4"
        blob = get_bucket().blob(blob_path)
        blob.upload_from_filename(temp_file_path, content_type='video/mp4')

        # Evidence stays PRIVATE (it used to be make_public(): anyone with the URL could watch it).
        # Consumers get a time-limited link; /evidence/<channel> issues fresh ones on demand.
        evidence_url = signed_url(blob_path, timedelta(days=6))
        call_ref.update({
            'evidencePath': blob_path,
            'evidenceUrl': evidence_url,
            'evidence_uploaded_at': datetime.now(timezone.utc)
        })

        return jsonify({
            "success": True,
            "message": "MP4 evidence video uploaded and linked successfully.",
            "evidenceUrl": evidence_url
        }), 200

    except Exception:
        log.exception("Evidence upload failed")
        if blob is not None:   # ROLLBACK orphaned upload
            try:
                if blob.exists():
                    blob.delete()
            except Exception:
                log.exception("Failed to clean up orphaned blob")
        return error("Evidence upload failed. Please try again.", 500)

    finally:
        _remove_file(temp_file_path)


from . import routes  # noqa: E402,F401