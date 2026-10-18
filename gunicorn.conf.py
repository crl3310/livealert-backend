import os

bind = f"0.0.0.0:{os.getenv('PORT', '8080')}"

# ONE process on purpose: the SSE hazard feed, per-user rate limits and the Firestore listeners all
# live in memory. Concurrency comes from threads instead.
workers = 1
worker_class = "gthread"
threads = int(os.getenv("GUNICORN_THREADS", "128"))   # each open SSE stream holds one thread (MAX_SSE_CLIENTS=80)

timeout = 120            # video analysis can poll Gemini for up to 60 s
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
