from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Callable, Sequence

from .errors import ReceiverError

_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")


def load_signing_secrets(raw: bytes) -> tuple[bytes, ...]:
    secrets = tuple(line.strip() for line in raw.splitlines() if line.strip())
    if not secrets or len(secrets) > 2:
        raise ValueError("one or two webhook signing secrets are required")
    if any(len(secret) < 32 or len(secret) > 4096 for secret in secrets):
        raise ValueError("webhook signing secrets must contain 32-4096 bytes")
    return secrets


def verify_signature(
    *,
    body: bytes,
    signature_header: str | None,
    timestamp_header: str | None,
    secrets: Sequence[bytes],
    tolerance_seconds: int = 300,
    now: Callable[[], float] = time.time,
) -> None:
    if not signature_header or not timestamp_header:
        raise ReceiverError("invalid_signature", 401, "signature headers are required")

    parts: dict[str, str] = {}
    for item in signature_header.split(","):
        key, separator, value = item.strip().partition("=")
        if not separator or key in parts:
            raise ReceiverError(
                "invalid_signature", 401, "signature header is malformed"
            )
        parts[key] = value
    if set(parts) != {"t", "v1"}:
        raise ReceiverError("invalid_signature", 401, "signature header is malformed")
    if parts["t"] != timestamp_header or not parts["t"].isdigit():
        raise ReceiverError("invalid_signature", 401, "signature timestamp is invalid")
    if not _SIGNATURE.fullmatch(parts["v1"]):
        raise ReceiverError("invalid_signature", 401, "signature digest is invalid")

    timestamp = int(parts["t"])
    if abs(int(now()) - timestamp) > tolerance_seconds:
        raise ReceiverError(
            "invalid_signature", 401, "signature timestamp is outside tolerance"
        )
    signed = str(timestamp).encode("ascii") + b"." + body
    received = bytes.fromhex(parts["v1"])
    if not any(
        hmac.compare_digest(hmac.new(secret, signed, hashlib.sha256).digest(), received)
        for secret in secrets
    ):
        raise ReceiverError("invalid_signature", 401, "signature is invalid")


def sign_for_test(body: bytes, secret: bytes, timestamp: int) -> str:
    digest = hmac.new(
        secret,
        str(timestamp).encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    return f"t={timestamp},v1={digest}"
