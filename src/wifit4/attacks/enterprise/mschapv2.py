"""
MSCHAPv2 challenge/response utilities.

Pure-Python implementation of the NT hash and challenge derivation used by
MSCHAPv2 (RFC 2759).  Used both by EapCapture (parsing) and unit tests.
"""
from __future__ import annotations

import hashlib
import hmac


def nt_hash(password: str) -> bytes:
    """MD4 of the UTF-16LE encoded password - the NT password hash."""
    return hashlib.new("md4", password.encode("utf-16-le")).digest()


def challenge_hash(
    peer_challenge: bytes,
    auth_challenge: bytes,
    username: str,
) -> bytes:
    """ChallengeHash per RFC 2759 §8.2."""
    digest = hashlib.sha1(
        peer_challenge + auth_challenge + username.encode()
    ).digest()
    return digest[:8]


def nt_response(
    auth_challenge: bytes,
    peer_challenge: bytes,
    username: str,
    password: str,
) -> bytes:
    """Full NTResponse per RFC 2759 §8.1 - for offline verification only."""
    ch = challenge_hash(peer_challenge, auth_challenge, username)
    pw_hash = nt_hash(password)
    # Pad to 21 bytes, split into three 7-byte DES keys
    padded = pw_hash + b"\x00" * (21 - len(pw_hash))
    result = b""
    for i in range(3):
        key_bytes = padded[i * 7 : i * 7 + 7]
        result += _des_ecb(key_bytes, ch)
    return result


def verify_response(
    auth_challenge: bytes,
    peer_challenge: bytes,
    username: str,
    password: str,
    response: bytes,
) -> bool:
    expected = nt_response(auth_challenge, peer_challenge, username, password)
    return hmac.compare_digest(expected, response)


def _des_ecb(key7: bytes, data8: bytes) -> bytes:
    """DES-ECB with a 7-byte key expanded to 8 bytes (odd-parity)."""
    from Crypto.Cipher import DES  # pycryptodome - optional dep
    key8 = _expand_des_key(key7)
    cipher = DES.new(key8, DES.MODE_ECB)
    return cipher.encrypt(data8)


def _expand_des_key(key7: bytes) -> bytes:
    """Expand 7-byte key to 8-byte DES key with odd parity bits."""
    bits = 0
    for b in key7:
        bits = (bits << 8) | b
    key8 = bytearray(8)
    for i in range(7, -1, -1):
        key8[i] = (bits & 0x7F) << 1
        bits >>= 7
    # set odd parity
    for i in range(8):
        byte = key8[i]
        parity = bin(byte).count("1") % 2
        if parity == 0:
            key8[i] ^= 1
    return bytes(key8)
