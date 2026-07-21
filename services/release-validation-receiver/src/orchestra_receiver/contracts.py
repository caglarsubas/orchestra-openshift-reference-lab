from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from .errors import ReceiverError

EVENT_TYPE = "release.validation.completed.v1"
CONTENT_TYPE = "application/cloudevents+json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,99}$")
_STATUSES = {"PASSED", "ROLLBACK_RECOMMENDED", "STALE", "CANCELLED"}
_RECOMMENDATION = {
    "PASSED": "continue",
    "ROLLBACK_RECOMMENDED": "rollback",
    "STALE": "hold",
    "CANCELLED": "hold",
}


@dataclass(frozen=True)
class ReleaseAction:
    event_id: str
    organization_id: str
    validation_id: str
    state_version: int
    recommendation: str
    release_id: str
    deployment_id: str
    environment: str
    artifact_digest: str
    evidence_digest: str | None
    body_digest: str

    def dispatch_payload(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "eventId": self.event_id,
            "organizationId": self.organization_id,
            "validationId": self.validation_id,
            "stateVersion": self.state_version,
            "recommendation": self.recommendation,
            "release": {
                "releaseId": self.release_id,
                "deploymentId": self.deployment_id,
                "environment": self.environment,
                "artifactDigest": self.artifact_digest,
            },
            "evidenceDigest": self.evidence_digest,
            "authority": {
                "recommendationOnly": True,
                "deploymentOwner": "tenant_ci_cd_or_gitops",
                "platformDeploysOrRollsBack": False,
            },
        }


def _object(value: Any, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiverError("invalid_cloud_event", 400, f"{field} must be an object")
    if set(value) != keys:
        raise ReceiverError(
            "invalid_cloud_event",
            400,
            f"{field} contains missing or unsupported properties",
        )
    return value


def _string(value: Any, field: str, max_length: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or value.strip() != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ReceiverError("invalid_cloud_event", 400, f"{field} is invalid")
    return value


def _positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or value < 1 or value > 9_007_199_254_740_991:
        raise ReceiverError("invalid_cloud_event", 400, f"{field} is invalid")
    return value


def _digest(value: Any, field: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    result = _string(value, field, 71)
    if not _DIGEST.fullmatch(result):
        raise ReceiverError("invalid_cloud_event", 400, f"{field} is invalid")
    return result


def _instant(value: Any, field: str) -> str:
    result = _string(value, field, 40)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReceiverError(
            "invalid_cloud_event", 400, f"{field} is invalid"
        ) from error
    if (
        parsed.tzinfo != timezone.utc
        or parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != result
    ):
        raise ReceiverError("invalid_cloud_event", 400, f"{field} is invalid")
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def parse_event(body: bytes) -> ReleaseAction:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON property")
            result[key] = value
        return result

    try:
        decoded = body.decode("utf-8")
        parsed = json.loads(
            decoded,
            object_pairs_hook=strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReceiverError("invalid_json", 400, "body must be UTF-8 JSON") from error

    root = _object(
        parsed,
        "CloudEvent",
        {
            "specversion",
            "id",
            "type",
            "source",
            "subject",
            "time",
            "datacontenttype",
            "data",
        },
    )
    if root["specversion"] != "1.0" or root["type"] != EVENT_TYPE:
        raise ReceiverError(
            "invalid_cloud_event", 400, "CloudEvent contract is unsupported"
        )
    if root["datacontenttype"] != "application/json":
        raise ReceiverError(
            "invalid_cloud_event", 400, "CloudEvent data content type is invalid"
        )
    event_id = _string(root["id"], "id")

    data = _object(
        root["data"],
        "data",
        {
            "version",
            "organizationId",
            "validation",
            "release",
            "evidence",
            "recommendation",
            "authority",
        },
    )
    if data["version"] != 1:
        raise ReceiverError("invalid_cloud_event", 400, "data.version is unsupported")
    organization_id = _string(data["organizationId"], "organizationId", 300)

    validation = _object(
        data["validation"],
        "validation",
        {
            "id",
            "validationVersion",
            "stateVersion",
            "status",
            "reasonCodes",
            "completedAt",
        },
    )
    validation_id = _string(validation["id"], "validation.id", 300)
    _positive_integer(validation["validationVersion"], "validation.validationVersion")
    state_version = _positive_integer(
        validation["stateVersion"], "validation.stateVersion"
    )
    status = _string(validation["status"], "validation.status", 32)
    if status not in _STATUSES:
        raise ReceiverError(
            "invalid_cloud_event", 400, "validation.status is unsupported"
        )
    reason_codes = validation["reasonCodes"]
    if not isinstance(reason_codes, list) or len(reason_codes) > 64:
        raise ReceiverError(
            "invalid_cloud_event", 400, "validation.reasonCodes is invalid"
        )
    if any(
        not isinstance(code, str) or not _REASON.fullmatch(code)
        for code in reason_codes
    ):
        raise ReceiverError(
            "invalid_cloud_event", 400, "validation.reasonCodes is invalid"
        )
    if reason_codes != sorted(set(reason_codes)):
        raise ReceiverError(
            "invalid_cloud_event",
            400,
            "validation.reasonCodes must be unique and sorted",
        )
    completed_at = _instant(validation["completedAt"], "validation.completedAt")

    release = _object(
        data["release"],
        "release",
        {"releaseId", "deploymentId", "environment", "artifactId", "artifactDigest"},
    )
    release_id = _string(release["releaseId"], "release.releaseId", 300)
    deployment_id = _string(release["deploymentId"], "release.deploymentId", 300)
    environment = _string(release["environment"], "release.environment", 64)
    _string(release["artifactId"], "release.artifactId", 300)
    artifact_digest = _digest(release["artifactDigest"], "release.artifactDigest")
    assert artifact_digest is not None

    evidence = _object(
        data["evidence"],
        "evidence",
        {
            "attestationId",
            "gateDecisionId",
            "activationReceiptId",
            "policyDigest",
            "thresholdDigest",
            "evaluatorVersionDigest",
            "evidenceDigest",
        },
    )
    for field in ("attestationId", "gateDecisionId", "activationReceiptId"):
        _string(evidence[field], f"evidence.{field}", 300)
    _digest(evidence["policyDigest"], "evidence.policyDigest")
    _digest(evidence["thresholdDigest"], "evidence.thresholdDigest")
    _digest(evidence["evaluatorVersionDigest"], "evidence.evaluatorVersionDigest", True)
    evidence_digest = _digest(
        evidence["evidenceDigest"], "evidence.evidenceDigest", True
    )

    recommendation = _string(data["recommendation"], "recommendation", 16)
    if recommendation != _RECOMMENDATION[status]:
        raise ReceiverError(
            "invalid_cloud_event", 400, "recommendation does not match status"
        )
    authority = _object(
        data["authority"],
        "authority",
        {"recommendationOnly", "deploymentOwner", "platformDeploysOrRollsBack"},
    )
    if authority != {
        "recommendationOnly": True,
        "deploymentOwner": "tenant_ci_cd_or_gitops",
        "platformDeploysOrRollsBack": False,
    }:
        raise ReceiverError("invalid_cloud_event", 400, "authority boundary is invalid")

    # Match JavaScript encodeURIComponent used by the platform event builder.
    component_safe = "-_.!~*'()"
    expected_source = (
        f"prometa://organizations/{quote(organization_id, safe=component_safe)}"
    )
    expected_subject = (
        f"release-validations/{quote(validation_id, safe=component_safe)}"
    )
    if root["source"] != expected_source or root["subject"] != expected_subject:
        raise ReceiverError(
            "invalid_cloud_event", 400, "CloudEvent identity is invalid"
        )
    if root["time"] != completed_at:
        raise ReceiverError("invalid_cloud_event", 400, "CloudEvent time is invalid")

    return ReleaseAction(
        event_id=event_id,
        organization_id=organization_id,
        validation_id=validation_id,
        state_version=state_version,
        recommendation=recommendation,
        release_id=release_id,
        deployment_id=deployment_id,
        environment=environment,
        artifact_digest=artifact_digest,
        evidence_digest=evidence_digest,
        body_digest=f"sha256:{hashlib.sha256(body).hexdigest()}",
    )


def validate_transport_headers(headers: dict[str, str], action: ReleaseAction) -> None:
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != CONTENT_TYPE:
        raise ReceiverError(
            "invalid_content_type", 415, f"Content-Type must be {CONTENT_TYPE}"
        )
    expected = {
        "x-prometa-event-id": action.event_id,
        "idempotency-key": action.event_id,
        "x-prometa-event-type": EVENT_TYPE,
        "x-prometa-state-version": str(action.state_version),
    }
    if any(headers.get(name) != value for name, value in expected.items()):
        raise ReceiverError(
            "event_header_mismatch", 400, "transport identity is invalid"
        )
