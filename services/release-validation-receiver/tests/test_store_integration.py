from __future__ import annotations

import os
import unittest
from concurrent.futures import ThreadPoolExecutor

from orchestra_receiver.errors import ReceiverError
from orchestra_receiver.migrate import apply_migrations
from orchestra_receiver.store import PostgresStore

from .helpers import action, digest


@unittest.skipUnless(
    os.environ.get("RECEIVER_TEST_DATABASE_URL"), "PostgreSQL test URL is required"
)
class PostgresStoreIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.database_url = os.environ["RECEIVER_TEST_DATABASE_URL"]
        apply_migrations(cls.database_url)
        cls.store = PostgresStore(cls.database_url, min_size=1, max_size=12)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.store.close()

    def setUp(self) -> None:
        with self.store.pool.connection() as connection:
            connection.execute(
                """
                TRUNCATE orchestra_lab_receiver.action_reconciliations,
                         orchestra_lab_receiver.action_outbox,
                         orchestra_lab_receiver.validation_heads,
                         orchestra_lab_receiver.inbox_events
                RESTART IDENTITY CASCADE
                """
            )
            connection.commit()

    def test_monotonic_admission_duplicate_stale_and_conflict(self) -> None:
        applied = self.store.admit(action())
        self.assertEqual((applied.outcome, applied.action_state), ("applied", "queued"))
        self.assertEqual(self.store.admit(action()).outcome, "duplicate")
        with self.assertRaisesRegex(ReceiverError, "state version"):
            self.store.admit(action(event_id="event-conflict", state_version=4))

        next_action = action(event_id="event-5", state_version=5)
        self.assertEqual(self.store.admit(next_action).outcome, "applied")
        stale = action(event_id="event-3", state_version=3)
        self.assertEqual(self.store.admit(stale).outcome, "stale")
        self.assertIsNone(self.store.event_status("event-3")["action_status"])
        with self.assertRaisesRegex(ReceiverError, "state version"):
            self.store.admit(action(event_id="event-3-conflict", state_version=3))

    def test_concurrent_duplicate_executes_one_durable_admission(self) -> None:
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(
                pool.map(lambda _index: self.store.admit(action()).outcome, range(8))
            )
        self.assertEqual(outcomes.count("applied"), 1)
        self.assertEqual(outcomes.count("duplicate"), 7)
        self.assertEqual(self.store.status_counts(), {"PENDING": 1})

    def test_claim_retry_delivery_and_indeterminate_reconciliation(self) -> None:
        self.store.admit(action())
        claimed = self.store.claim_next("worker-1", 60)
        self.assertIsNotNone(claimed)
        self.store.mark_retry("event-4", "worker-1", "github_503", 503, 0)
        claimed = self.store.claim_next("worker-2", 60)
        self.assertEqual(claimed.attempt_count, 2)
        self.store.mark_delivered("event-4", "worker-2", "github-request-1")
        self.assertEqual(
            self.store.event_status("event-4")["action_status"], "DELIVERED"
        )

        second = action(event_id="event-5", state_version=5)
        self.store.admit(second)
        self.store.claim_next("worker-1", 60)
        self.store.mark_indeterminate("event-5", "worker-1", "network_unknown", None)
        self.assertEqual(
            self.store.event_status("event-5")["action_status"], "INDETERMINATE"
        )
        self.store.reconcile("event-5", "RETRY", digest("proof"), digest("operator"))
        self.assertEqual(self.store.event_status("event-5")["action_status"], "RETRY")
        with self.assertRaisesRegex(ReceiverError, "only indeterminate"):
            self.store.reconcile(
                "event-5", "DELIVERED", digest("proof-2"), digest("operator")
            )

    def test_expired_claim_becomes_indeterminate_without_replay(self) -> None:
        self.store.admit(action())
        self.store.claim_next("worker-1", 15)
        with self.store.pool.connection() as connection:
            connection.execute(
                """
                UPDATE orchestra_lab_receiver.action_outbox
                SET lease_expires_at = clock_timestamp() - interval '1 second'
                WHERE event_id = 'event-4'
                """
            )
            connection.commit()
        self.assertIsNone(self.store.claim_next("worker-2", 15))
        status = self.store.event_status("event-4")
        self.assertEqual(status["action_status"], "INDETERMINATE")
        self.assertEqual(status["last_error_code"], "worker_lease_expired")

    def test_migration_is_idempotent_and_digest_bound(self) -> None:
        apply_migrations(self.database_url)
        with self.store.pool.connection() as connection:
            original = connection.execute(
                """
                SELECT script_digest FROM orchestra_lab_receiver.schema_migrations
                WHERE version = 1
                """
            ).fetchone()["script_digest"]
            connection.execute(
                """
                UPDATE orchestra_lab_receiver.schema_migrations
                SET script_digest = %s WHERE version = 1
                """,
                (digest("tampered-migration"),),
            )
            connection.commit()
        try:
            with self.assertRaisesRegex(RuntimeError, "digest does not match"):
                apply_migrations(self.database_url)
        finally:
            with self.store.pool.connection() as connection:
                connection.execute(
                    """
                    UPDATE orchestra_lab_receiver.schema_migrations
                    SET script_digest = %s WHERE version = 1
                    """,
                    (original,),
                )
                connection.commit()


if __name__ == "__main__":
    unittest.main()
