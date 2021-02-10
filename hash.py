import hashlib


def sha256(data: bytes) -> bytes:
    """SHA-256 hash.

    This returns a bytes object of length 32"""
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Bitcoin's hash function (double SHA-256)

    This returns a bytes object of length 32."""
    return sha256(sha256(data))
