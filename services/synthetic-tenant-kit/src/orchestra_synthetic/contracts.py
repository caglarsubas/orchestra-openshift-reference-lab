from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class SyntheticError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def strict_json(body: bytes, *, maximum_bytes: int) -> Any:
    if not body or len(body) > maximum_bytes:
        raise SyntheticError("request_invalid", 400)

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON property")
            result[key] = value
        return result

    try:
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise SyntheticError("request_invalid_json", 400) from error


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise SyntheticError("request_invalid", 400) from error


def parse_runtime_request(body: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    value = strict_json(body, maximum_bytes=maximum_bytes)
    if not isinstance(value, dict) or set(value) != {"requestId", "input"}:
        raise SyntheticError("request_invalid", 400)
    request_id = value["requestId"]
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise SyntheticError("request_invalid", 400)
    if not isinstance(value["input"], dict):
        raise SyntheticError("request_invalid", 400)
    canonical_json(value)
    return value


def parse_runtime_response(body: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    value = strict_json(body, maximum_bytes=maximum_bytes)
    if not isinstance(value, dict) or set(value) != {
        "requestId",
        "output",
        "modelName",
        "attempts",
        "toolCalls",
        "usedFallback",
    }:
        raise SyntheticError("runtime_response_invalid", 502)
    if not isinstance(value["requestId"], str) or not _REQUEST_ID.fullmatch(
        value["requestId"]
    ):
        raise SyntheticError("runtime_response_invalid", 502)
    if not isinstance(value["output"], dict):
        raise SyntheticError("runtime_response_invalid", 502)
    if not isinstance(value["modelName"], str) or not value["modelName"]:
        raise SyntheticError("runtime_response_invalid", 502)
    if type(value["attempts"]) is not int or not 1 <= value["attempts"] <= 100:
        raise SyntheticError("runtime_response_invalid", 502)
    if type(value["toolCalls"]) is not int or not 0 <= value["toolCalls"] <= 100:
        raise SyntheticError("runtime_response_invalid", 502)
    if type(value["usedFallback"]) is not bool:
        raise SyntheticError("runtime_response_invalid", 502)
    canonical_json(value)
    return value


def read_file(path: str, *, maximum_bytes: int = 262_144) -> bytes:
    target = Path(path)
    # Kubernetes projected Secret and ConfigMap files are symlinks into ..data.
    if not target.is_file() or not target.resolve(strict=True).is_file():
        raise RuntimeError(f"mounted path is not a regular file: {path}")
    raw = target.read_bytes()
    if not raw or len(raw) > maximum_bytes:
        raise RuntimeError(f"mounted file has invalid size: {path}")
    return raw.rstrip(b"\r\n")


def identity_digest(issuer: str, subject: str) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            issuer.encode("utf-8") + b"\x00" + subject.encode("utf-8")
        ).hexdigest()
    )
