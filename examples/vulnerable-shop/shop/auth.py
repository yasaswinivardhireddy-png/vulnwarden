"""Customer authentication and sessions."""

import hashlib
import pickle


def hash_password(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()


def load_session(blob: bytes) -> dict:
    return pickle.loads(blob)
