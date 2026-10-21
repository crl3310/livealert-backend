import logging
import os

from dotenv import load_dotenv

load_dotenv()  # no-op in production when the platform injects real env vars

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("livealert")

from flask import Flask, jsonify, request
from flask_mailman import Mail
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app_core import get_db, init_firebase
from app_security import env_flag, error, limiter

# --- Fail fast on missing configuration --------------------------------------
_REQUIRED_ENV = [
    "FIREBASE_WEB_API_KEY", "GEMINI_API_KEY", "AGORA_APP_ID", "AGORA_APP_CERTIFICATE",
    "MAIL_USERNAME", "MAIL_PASSWORD",
]
_missing = [k for k in _REQUIRED_ENV if not os.getenv(k)]
if _missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(_missing)}")

app = Flask(__name__)

# Reject oversized uploads before they are read (videos / photos).
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "100")) * 1024 * 1024

# --- Email SMTP -------------------------------------------------------------
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_USERNAME"),
    MAIL_TIMEOUT=10,
)
mail = Mail(app)

# --- Reverse proxy awareness (so rate limiting sees the real client IP) ------
_proxies = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))
if _proxies:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxies, x_proto=_proxies, x_host=_proxies)

limiter.init_app(app)
init_firebase()  # raises if credentials are bad: better to crash at boot than 500 on every request

# --- Blueprints -------------------------------------------------------------
from auth.register import auth_bp
import auth.login
import auth.verify
import auth.responder_login
import auth.responder_changepass
import auth.refresh
import responder.location
from live.history_user import history_user_bp
from live.live import live_bp
from community.hazard import community_bp
from responder.duty import responder_bp
from responder.history_unit import responder_history_bp
from responder.resolve import responder_resolve_bp
import auth.forgotpassword
import auth.changepassword

app.register_blueprint(community_bp, url_prefix="/api/community")
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(live_bp, url_prefix="/api/live")
app.register_blueprint(responder_bp, url_prefix="/api/responder")
app.register_blueprint(responder.location.responder_bp, url_prefix="/api/responder")
app.register_blueprint(history_user_bp, url_prefix="/api/live")
app.register_blueprint(responder_history_bp, url_prefix="/api/responder")
app.register_blueprint(responder_resolve_bp, url_prefix="/api/responder")



# --- Hardening --------------------------------------------------------------
@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


@app.errorhandler(Exception)
def handle_any_error(e):
    # JSON errors only; internal details are logged, never returned to the client.
    if isinstance(e, HTTPException):
        if e.code == 413:
            return error("Upload too large.", 413)
        return error(e.description or e.name, e.code or 500)
    log.exception("Unhandled error on %s %s", request.method, request.path)
    return error("Internal server error.", 500)


@app.route("/", methods=["GET"])
def gateway_status():
    return jsonify({"status": "online", "message": "LiveAlert Main Gateway is active and linked to Firestore!"})


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


# --- Realtime Firestore listeners -------------------------------------------
# These run inside this process, so run exactly ONE instance/worker (see DEPLOYMENT.md).
def _start_listeners():
    try:
        from responder.listener import start_active_calls_listener
        from live.user_listener import setup_active_calls_listener

        setup_active_calls_listener(get_db())
        start_active_calls_listener()
    except Exception:
        log.exception("Failed to start Firestore listeners")


if int(os.getenv("WEB_CONCURRENCY", "1")) > 1:
    log.warning("WEB_CONCURRENCY > 1: listeners and the SSE feed assume a single process!")

if env_flag("RUN_LISTENERS", True):
    _start_listeners()


if __name__ == "__main__":
    # Local development only. Production uses gunicorn (see Dockerfile / gunicorn.conf.py).
    # The Werkzeug debugger is deliberately never enabled: it allows remote code execution.
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False, use_reloader=False)