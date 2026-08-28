"""Short-lived in-memory cache for SSH-backed API reads."""

import threading
import time

_LOCK = threading.Lock()
_STORE = {}


def get(key, ttl):
    now = time.monotonic()
    with _LOCK:
        item = _STORE.get(key)
        if not item:
            return None
        ts, value = item
        if now - ts > ttl:
            _STORE.pop(key, None)
            return None
        return value


def set(key, value):
    with _LOCK:
        _STORE[key] = (time.monotonic(), value)


def invalidate(key):
    with _LOCK:
        _STORE.pop(key, None)


def invalidate_prefix(prefix):
    with _LOCK:
        for key in [k for k in _STORE if k.startswith(prefix)]:
            _STORE.pop(key, None)
