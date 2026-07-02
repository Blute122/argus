"""TOTP (RFC 6238) multi-factor auth — dependency-free (stdlib only).

Keeps the install lean for self-hosters: no pyotp/qrcode. The frontend builds
the QR from the otpauth:// URI returned at enrollment.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

_DIGITS = 6
_PERIOD = 30


def generate_secret() -> str:
    """Return a base32 secret (no padding) suitable for authenticator apps."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    padding = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** _DIGITS)
    return str(code).zfill(_DIGITS)


def verify(secret_b32: str, code: str, window: int = 1) -> bool:
    """Verify a TOTP code, allowing +/- `window` periods for clock skew."""
    if not secret_b32 or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    counter = int(time.time() // _PERIOD)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, counter + drift), code):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Argus") -> str:
    """otpauth:// URI the frontend renders as a QR code."""
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&digits={_DIGITS}&period={_PERIOD}")
