"""HTTP caching helpers."""

import hashlib


def etag(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()
