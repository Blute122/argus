"""Minimal in-memory rate limiting (dependency-free).

Fixed-window counter keyed by client IP + bucket name. Adequate for a
self-hosted single-node deployment; swap for Redis-backed limiting if the app
is ever scaled horizontally.
"""

import threading
import time

from fastapi import HTTPException, Request

_lock = threading.Lock()
_hits: dict[str, list] = {}  # key -> [window_start_epoch, count]


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with _lock:
        entry = _hits.get(key)
        if entry is None or now - entry[0] >= window:
            _hits[key] = [now, 1]
            return True
        if entry[1] >= limit:
            return False
        entry[1] += 1
        return True


def rate_limiter(bucket: str, limit: int, window: int):
    """Return a FastAPI dependency enforcing `limit` requests per `window` sec
    per client IP for the given bucket. limit <= 0 disables the check."""
    def dependency(request: Request):
        if limit <= 0:
            return
        key = f"{bucket}:{_client_ip(request)}"
        if not _check(key, limit, window):
            raise HTTPException(status_code=429, detail="Too many requests, slow down.")
    return dependency
