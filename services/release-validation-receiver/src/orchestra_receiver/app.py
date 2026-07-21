from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
from typing import Any, Callable

from .config import ApiConfig
from .contracts import parse_event, validate_transport_headers
from .errors import ReceiverError
from .signing import verify_signature
from .store import PostgresStore

_EVENT_PATH = re.compile(r"^/internal/v1/actions/([^/]+)$")
_RECONCILE_PATH = re.compile(r"^/internal/v1/actions/([^/]+)/reconcile$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _json_response(
    start_response: Callable[..., Any], status: int, payload: dict[str, Any]
):
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    start_response(
        f"{status} {_status_text(status)}",
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body]


def _status_text(status: int) -> str:
    return {
        200: "OK",
        202: "Accepted",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        413: "Payload Too Large",
        415: "Unsupported Media Type",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(status, "Error")


def _headers(environ: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in environ.items():
        if name.startswith("HTTP_"):
            result[name[5:].replace("_", "-").lower()] = str(value)
    if environ.get("CONTENT_TYPE"):
        result["content-type"] = str(environ["CONTENT_TYPE"])
    return result


class ReceiverApplication:
    def __init__(self, config: ApiConfig, store: PostgresStore):
        if len(config.admin_token) < 32 or len(config.admin_token) > 4096:
            raise ValueError("admin token must contain 32-4096 bytes")
        self.config = config
        self.store = store

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]):
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))
        try:
            if method == "GET" and path == "/healthz":
                return _json_response(start_response, 200, {"status": "alive"})
            if method == "GET" and path == "/readyz":
                ready = self.store.ready()
                return _json_response(
                    start_response, 200 if ready else 503, {"ready": ready}
                )
            if method == "GET" and path == "/metrics":
                return self._metrics(start_response)
            if method == "POST" and path == "/v1/release-validation/completed":
                return self._webhook(environ, start_response)
            status_match = _EVENT_PATH.fullmatch(path)
            if method == "GET" and status_match:
                self._authorize(environ)
                status = self.store.event_status(status_match.group(1))
                if not status:
                    raise ReceiverError("event_not_found", 404, "event was not found")
                return _json_response(start_response, 200, status)
            reconcile_match = _RECONCILE_PATH.fullmatch(path)
            if method == "POST" and reconcile_match:
                self._authorize(environ)
                return self._reconcile(
                    environ, start_response, reconcile_match.group(1)
                )
            if path in {
                "/v1/release-validation/completed",
                "/healthz",
                "/readyz",
                "/metrics",
            }:
                raise ReceiverError("method_not_allowed", 405, "method is not allowed")
            raise ReceiverError("not_found", 404, "path was not found")
        except ReceiverError as error:
            return _json_response(
                start_response,
                error.status,
                {"error": {"code": error.code, "message": str(error)}},
            )
        except Exception:
            return _json_response(
                start_response,
                500,
                {"error": {"code": "internal_error", "message": "request failed"}},
            )

    def _read_body(self, environ: dict[str, Any], maximum: int | None = None) -> bytes:
        limit = maximum or self.config.maximum_body_bytes
        raw_length = environ.get("CONTENT_LENGTH", "")
        try:
            length = int(raw_length) if raw_length else 0
        except ValueError as error:
            raise ReceiverError(
                "invalid_content_length", 400, "Content-Length is invalid"
            ) from error
        if length < 0 or length > limit:
            raise ReceiverError("body_too_large", 413, "request body is too large")
        stream = environ.get("wsgi.input", io.BytesIO())
        body = stream.read(length) if length else stream.read(limit + 1)
        if len(body) > limit:
            raise ReceiverError("body_too_large", 413, "request body is too large")
        if not body:
            raise ReceiverError("invalid_json", 400, "request body is required")
        return body

    def _webhook(self, environ: dict[str, Any], start_response: Callable[..., Any]):
        headers = _headers(environ)
        body = self._read_body(environ)
        verify_signature(
            body=body,
            signature_header=headers.get("x-prometa-signature"),
            timestamp_header=headers.get("x-prometa-timestamp"),
            secrets=self.config.signing_secrets,
            tolerance_seconds=self.config.signature_tolerance_seconds,
        )
        action = parse_event(body)
        validate_transport_headers(headers, action)
        result = self.store.admit(action)
        return _json_response(
            start_response,
            202 if result.outcome == "applied" else 200,
            {
                "outcome": result.outcome,
                "eventId": result.event_id,
                "validationId": result.validation_id,
                "stateVersion": result.state_version,
                "recommendation": result.recommendation,
                "actionState": result.action_state,
            },
        )

    def _authorize(self, environ: dict[str, Any]) -> None:
        authorization = _headers(environ).get("authorization", "")
        prefix = "Bearer "
        supplied = (
            authorization[len(prefix) :].encode("utf-8")
            if authorization.startswith(prefix)
            else b""
        )
        if not supplied or not hmac.compare_digest(supplied, self.config.admin_token):
            raise ReceiverError("unauthorized", 401, "admin authorization is invalid")

    def _reconcile(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
        event_id: str,
    ):
        try:
            payload = json.loads(self._read_body(environ, 4096))
        except json.JSONDecodeError as error:
            raise ReceiverError(
                "invalid_json", 400, "reconciliation body is invalid"
            ) from error
        if not isinstance(payload, dict) or set(payload) != {
            "resolvedStatus",
            "evidenceDigest",
            "actorDigest",
        }:
            raise ReceiverError(
                "invalid_reconciliation", 400, "reconciliation contract is invalid"
            )
        if payload["resolvedStatus"] not in {"RETRY", "DELIVERED", "DEAD_LETTER"}:
            raise ReceiverError(
                "invalid_reconciliation", 400, "resolvedStatus is invalid"
            )
        if not isinstance(payload["evidenceDigest"], str) or not _DIGEST.fullmatch(
            payload["evidenceDigest"]
        ):
            raise ReceiverError(
                "invalid_reconciliation", 400, "evidenceDigest is invalid"
            )
        if not isinstance(payload["actorDigest"], str) or not _DIGEST.fullmatch(
            payload["actorDigest"]
        ):
            raise ReceiverError("invalid_reconciliation", 400, "actorDigest is invalid")
        self.store.reconcile(
            event_id,
            payload["resolvedStatus"],
            payload["evidenceDigest"],
            payload["actorDigest"],
        )
        return _json_response(
            start_response,
            200,
            {
                "eventId": event_id,
                "resolvedStatus": payload["resolvedStatus"],
                "reconciliationDigest": f"sha256:{hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}",
            },
        )

    def _metrics(self, start_response: Callable[..., Any]):
        counts = self.store.status_counts()
        lines = [
            "# HELP orchestra_receiver_actions Actions by durable delivery state.",
            "# TYPE orchestra_receiver_actions gauge",
        ]
        for status in (
            "PENDING",
            "CLAIMED",
            "RETRY",
            "DELIVERED",
            "INDETERMINATE",
            "DEAD_LETTER",
        ):
            lines.append(
                f'orchestra_receiver_actions{{status="{status.lower()}"}} {counts.get(status, 0)}'
            )
        body = ("\n".join(lines) + "\n").encode("ascii")
        start_response(
            "200 OK",
            [
                ("Content-Type", "text/plain; version=0.0.4"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]


_default_application: ReceiverApplication | None = None


def application(environ: dict[str, Any], start_response: Callable[..., Any]):
    global _default_application
    if _default_application is None:
        config = ApiConfig.from_env()
        _default_application = ReceiverApplication(
            config, PostgresStore(config.database_url)
        )
    return _default_application(environ, start_response)
