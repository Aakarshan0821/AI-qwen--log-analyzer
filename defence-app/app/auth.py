import base64
import hashlib
import hmac
import json
import time

SESSION_COOKIE_NAME = "defence_session"


def _b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def create_session_token(email: str, secret: str, max_age_seconds: int) -> str:
    payload = {"email": email, "exp": int(time.time()) + max_age_seconds}
    payload_raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_b64 = _b64_encode(payload_raw)
    signature = hmac.new(secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64_encode(signature)}"


def verify_session_token(token: str, secret: str) -> str | None:
    if "." not in token:
        return None

    payload_b64, signature_b64 = token.split(".", 1)
    expected_signature = hmac.new(
        secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
    ).digest()
    expected_signature_b64 = _b64_encode(expected_signature)
    if not hmac.compare_digest(signature_b64, expected_signature_b64):
        return None

    try:
        payload_raw = _b64_decode(payload_b64)
        payload = json.loads(payload_raw.decode("utf-8"))
        exp = int(payload.get("exp", 0))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None

    if exp <= int(time.time()):
        return None

    email = payload.get("email")
    return email if isinstance(email, str) and email else None
