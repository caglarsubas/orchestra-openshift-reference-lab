from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .contracts import ReleaseAction
from .errors import ReceiverError


@dataclass(frozen=True)
class AdmissionResult:
    outcome: str
    event_id: str
    validation_id: str
    state_version: int
    recommendation: str
    action_state: str | None


@dataclass(frozen=True)
class ClaimedAction:
    action: ReleaseAction
    attempt_count: int


class PostgresStore:
    def __init__(self, database_url: str, *, min_size: int = 1, max_size: int = 8):
        self.pool = ConnectionPool(
            database_url,
            min_size=min_size,
            max_size=max_size,
            timeout=5,
            max_waiting=64,
            kwargs={"row_factory": dict_row},
            open=True,
        )

    def close(self) -> None:
        self.pool.close()

    def ready(self) -> bool:
        try:
            with self.pool.connection() as connection:
                result = connection.execute("SELECT 1 AS ready").fetchone()
                return bool(result and result["ready"] == 1)
        except Exception:
            return False

    def admit(self, action: ReleaseAction) -> AdmissionResult:
        lock_key = f"{action.organization_id}:{action.validation_id}"
        with self.pool.connection() as connection, connection.transaction():
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,)
            )
            existing = connection.execute(
                """
                SELECT body_digest, disposition, validation_id, state_version, recommendation
                FROM orchestra_lab_receiver.inbox_events
                WHERE event_id = %s
                """,
                (action.event_id,),
            ).fetchone()
            if existing:
                if existing["body_digest"] != action.body_digest:
                    raise ReceiverError(
                        "event_id_conflict",
                        409,
                        "event id already owns different bytes",
                    )
                return AdmissionResult(
                    outcome="duplicate",
                    event_id=action.event_id,
                    validation_id=existing["validation_id"],
                    state_version=existing["state_version"],
                    recommendation=existing["recommendation"],
                    action_state=(
                        "queued" if existing["disposition"] == "APPLIED" else None
                    ),
                )

            version_owner = connection.execute(
                """
                SELECT event_id
                FROM orchestra_lab_receiver.inbox_events
                WHERE organization_id = %s AND validation_id = %s AND state_version = %s
                """,
                (action.organization_id, action.validation_id, action.state_version),
            ).fetchone()
            if version_owner:
                raise ReceiverError(
                    "state_version_conflict",
                    409,
                    "a different event already owns this validation state version",
                )

            head = connection.execute(
                """
                SELECT state_version, event_id, body_digest
                FROM orchestra_lab_receiver.validation_heads
                WHERE organization_id = %s AND validation_id = %s
                FOR UPDATE
                """,
                (action.organization_id, action.validation_id),
            ).fetchone()
            if head and action.state_version == head["state_version"]:
                raise ReceiverError(
                    "state_version_conflict",
                    409,
                    "a different event already owns this validation state version",
                )

            disposition = (
                "STALE"
                if head and action.state_version < head["state_version"]
                else "APPLIED"
            )
            connection.execute(
                """
                INSERT INTO orchestra_lab_receiver.inbox_events (
                  event_id, organization_id, validation_id, state_version, body_digest,
                  disposition, recommendation, release_id, deployment_id, environment,
                  artifact_digest, evidence_digest
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    action.event_id,
                    action.organization_id,
                    action.validation_id,
                    action.state_version,
                    action.body_digest,
                    disposition,
                    action.recommendation,
                    action.release_id,
                    action.deployment_id,
                    action.environment,
                    action.artifact_digest,
                    action.evidence_digest,
                ),
            )
            if disposition == "STALE":
                return AdmissionResult(
                    outcome="stale",
                    event_id=action.event_id,
                    validation_id=action.validation_id,
                    state_version=action.state_version,
                    recommendation=action.recommendation,
                    action_state=None,
                )

            connection.execute(
                """
                INSERT INTO orchestra_lab_receiver.validation_heads (
                  organization_id, validation_id, state_version, event_id,
                  body_digest, recommendation
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (organization_id, validation_id) DO UPDATE SET
                  state_version = EXCLUDED.state_version,
                  event_id = EXCLUDED.event_id,
                  body_digest = EXCLUDED.body_digest,
                  recommendation = EXCLUDED.recommendation,
                  updated_at = clock_timestamp()
                """,
                (
                    action.organization_id,
                    action.validation_id,
                    action.state_version,
                    action.event_id,
                    action.body_digest,
                    action.recommendation,
                ),
            )
            connection.execute(
                """
                INSERT INTO orchestra_lab_receiver.action_outbox (event_id, status)
                VALUES (%s, 'PENDING')
                """,
                (action.event_id,),
            )
            return AdmissionResult(
                outcome="applied",
                event_id=action.event_id,
                validation_id=action.validation_id,
                state_version=action.state_version,
                recommendation=action.recommendation,
                action_state="queued",
            )

    def claim_next(self, worker_id: str, lease_seconds: int) -> ClaimedAction | None:
        with self.pool.connection() as connection, connection.transaction():
            connection.execute(
                """
                UPDATE orchestra_lab_receiver.action_outbox
                SET status = 'INDETERMINATE', lease_owner = NULL, lease_expires_at = NULL,
                    last_error_code = 'worker_lease_expired',
                    indeterminate_at = clock_timestamp(), updated_at = clock_timestamp()
                WHERE status = 'CLAIMED' AND lease_expires_at < clock_timestamp()
                """
            )
            row = connection.execute(
                """
                SELECT i.*, o.attempt_count
                FROM orchestra_lab_receiver.action_outbox o
                JOIN orchestra_lab_receiver.inbox_events i USING (event_id)
                WHERE o.status IN ('PENDING', 'RETRY')
                  AND o.next_attempt_at <= clock_timestamp()
                ORDER BY o.next_attempt_at, o.created_at
                FOR UPDATE OF o SKIP LOCKED
                LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            updated = connection.execute(
                """
                UPDATE orchestra_lab_receiver.action_outbox
                SET status = 'CLAIMED', attempt_count = attempt_count + 1,
                    lease_owner = %s,
                    lease_expires_at = clock_timestamp() + (%s * interval '1 second'),
                    updated_at = clock_timestamp()
                WHERE event_id = %s
                RETURNING attempt_count
                """,
                (worker_id, lease_seconds, row["event_id"]),
            ).fetchone()
            assert updated is not None
            action = ReleaseAction(
                event_id=row["event_id"],
                organization_id=row["organization_id"],
                validation_id=row["validation_id"],
                state_version=row["state_version"],
                recommendation=row["recommendation"],
                release_id=row["release_id"],
                deployment_id=row["deployment_id"],
                environment=row["environment"],
                artifact_digest=row["artifact_digest"],
                evidence_digest=row["evidence_digest"],
                body_digest=row["body_digest"],
            )
            return ClaimedAction(action=action, attempt_count=updated["attempt_count"])

    def mark_delivered(
        self, event_id: str, worker_id: str, request_id: str | None
    ) -> None:
        self._complete(
            event_id,
            worker_id,
            """
            status = 'DELIVERED', github_request_id = %s, delivered_at = clock_timestamp(),
            lease_owner = NULL, lease_expires_at = NULL, last_error_code = NULL,
            last_http_status = 204
            """,
            (request_id,),
        )

    def mark_retry(
        self,
        event_id: str,
        worker_id: str,
        error_code: str,
        http_status: int | None,
        delay_seconds: int,
    ) -> None:
        self._complete(
            event_id,
            worker_id,
            """
            status = 'RETRY', next_attempt_at = clock_timestamp() + (%s * interval '1 second'),
            lease_owner = NULL, lease_expires_at = NULL, last_error_code = %s,
            last_http_status = %s
            """,
            (delay_seconds, error_code, http_status),
        )

    def mark_indeterminate(
        self, event_id: str, worker_id: str, error_code: str, http_status: int | None
    ) -> None:
        self._complete(
            event_id,
            worker_id,
            """
            status = 'INDETERMINATE', lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = %s, last_http_status = %s,
            indeterminate_at = clock_timestamp()
            """,
            (error_code, http_status),
        )

    def mark_dead_letter(
        self, event_id: str, worker_id: str, error_code: str, http_status: int | None
    ) -> None:
        self._complete(
            event_id,
            worker_id,
            """
            status = 'DEAD_LETTER', lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = %s, last_http_status = %s
            """,
            (error_code, http_status),
        )

    def _complete(
        self,
        event_id: str,
        worker_id: str,
        assignments: str,
        parameters: tuple[Any, ...],
    ) -> None:
        with self.pool.connection() as connection, connection.transaction():
            cursor = connection.execute(
                f"""
                UPDATE orchestra_lab_receiver.action_outbox
                SET {assignments}, updated_at = clock_timestamp()
                WHERE event_id = %s AND status = 'CLAIMED' AND lease_owner = %s
                """,
                (*parameters, event_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("action lease was lost")

    def reconcile(
        self,
        event_id: str,
        resolved_status: str,
        evidence_digest: str,
        actor_digest: str,
    ) -> None:
        if resolved_status not in {"RETRY", "DELIVERED", "DEAD_LETTER"}:
            raise ValueError("invalid resolved status")
        with self.pool.connection() as connection, connection.transaction():
            row = connection.execute(
                """
                SELECT status FROM orchestra_lab_receiver.action_outbox
                WHERE event_id = %s FOR UPDATE
                """,
                (event_id,),
            ).fetchone()
            if not row or row["status"] != "INDETERMINATE":
                raise ReceiverError(
                    "action_not_indeterminate",
                    409,
                    "only indeterminate actions can be reconciled",
                )
            connection.execute(
                """
                INSERT INTO orchestra_lab_receiver.action_reconciliations (
                  event_id, previous_status, resolved_status, evidence_digest, actor_digest
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    event_id,
                    row["status"],
                    resolved_status,
                    evidence_digest,
                    actor_digest,
                ),
            )
            connection.execute(
                """
                UPDATE orchestra_lab_receiver.action_outbox
                SET status = %s, next_attempt_at = clock_timestamp(),
                    last_error_code = 'operator_reconciled',
                    delivered_at = CASE WHEN %s = 'DELIVERED' THEN clock_timestamp() ELSE delivered_at END,
                    updated_at = clock_timestamp()
                WHERE event_id = %s
                """,
                (resolved_status, resolved_status, event_id),
            )

    def status_counts(self) -> dict[str, int]:
        with self.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT status, count(*)::bigint AS count
                FROM orchestra_lab_receiver.action_outbox GROUP BY status
                """
            ).fetchall()
        return {row["status"]: row["count"] for row in rows}

    def event_status(self, event_id: str) -> dict[str, Any] | None:
        with self.pool.connection() as connection:
            row = connection.execute(
                """
                SELECT i.event_id, i.validation_id, i.state_version, i.recommendation,
                       i.disposition, i.received_at, o.status AS action_status,
                       o.attempt_count, o.last_error_code, o.last_http_status,
                       o.delivered_at, o.indeterminate_at
                FROM orchestra_lab_receiver.inbox_events i
                LEFT JOIN orchestra_lab_receiver.action_outbox o USING (event_id)
                WHERE i.event_id = %s
                """,
                (event_id,),
            ).fetchone()
        if not row:
            return None
        return {
            key: value.isoformat().replace("+00:00", "Z")
            if isinstance(value, datetime)
            else value
            for key, value in row.items()
        }
