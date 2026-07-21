from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

from orchestra_receiver.contracts import ReleaseAction


def digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def event(
    event_id: str = "event-4",
    state_version: int = 4,
    status: str = "ROLLBACK_RECOMMENDED",
) -> dict[str, Any]:
    recommendation = {
        "PASSED": "continue",
        "ROLLBACK_RECOMMENDED": "rollback",
        "STALE": "hold",
        "CANCELLED": "hold",
    }[status]
    completed_at = "2026-07-20T11:30:00.000Z"
    data = {
        "version": 1,
        "organizationId": "org-1",
        "validation": {
            "id": "validation-1",
            "validationVersion": 1,
            "stateVersion": state_version,
            "status": status,
            "reasonCodes": ["explicit_runtime_failure"],
            "completedAt": completed_at,
        },
        "release": {
            "releaseId": "release-candidate",
            "deploymentId": "deployment-1",
            "environment": "prod",
            "artifactId": "artifact-1",
            "artifactDigest": digest("artifact"),
        },
        "evidence": {
            "attestationId": "attestation-1",
            "gateDecisionId": "gate-1",
            "activationReceiptId": "receipt-1",
            "policyDigest": digest("policy"),
            "thresholdDigest": digest("threshold"),
            "evaluatorVersionDigest": digest("evaluator"),
            "evidenceDigest": digest("evidence"),
        },
        "recommendation": recommendation,
        "authority": {
            "recommendationOnly": True,
            "deploymentOwner": "tenant_ci_cd_or_gitops",
            "platformDeploysOrRollsBack": False,
        },
    }
    return {
        "specversion": "1.0",
        "id": event_id,
        "type": "release.validation.completed.v1",
        "source": "prometa://organizations/org-1",
        "subject": "release-validations/validation-1",
        "time": completed_at,
        "datacontenttype": "application/json",
        "data": data,
    }


def event_body(**kwargs: Any) -> bytes:
    return json.dumps(event(**kwargs), separators=(",", ":"), sort_keys=True).encode()


def action(event_id: str = "event-4", state_version: int = 4) -> ReleaseAction:
    return ReleaseAction(
        event_id=event_id,
        organization_id="org-1",
        validation_id="validation-1",
        state_version=state_version,
        recommendation="rollback",
        release_id="release-candidate",
        deployment_id="deployment-1",
        environment="prod",
        artifact_digest=digest("artifact"),
        evidence_digest=digest("evidence"),
        body_digest=digest(f"body-{event_id}"),
    )


def clone_event(**kwargs: Any) -> dict[str, Any]:
    return deepcopy(event(**kwargs))
