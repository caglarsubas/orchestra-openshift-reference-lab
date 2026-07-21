from __future__ import annotations

import unittest

from orchestra_receiver.errors import (
    IndeterminateDispatchError,
    PermanentDispatchError,
    RetryableDispatchError,
)
from orchestra_receiver.github import DispatchReceipt
from orchestra_receiver.store import ClaimedAction
from orchestra_receiver.worker import DispatchWorker

from .helpers import action


class FakeStore:
    def __init__(self, claimed=None):
        self.claimed = claimed
        self.calls = []

    def claim_next(self, worker_id, lease_seconds):
        self.calls.append(("claim", worker_id, lease_seconds))
        result, self.claimed = self.claimed, None
        return result

    def mark_delivered(self, *args):
        self.calls.append(("delivered", *args))

    def mark_retry(self, *args):
        self.calls.append(("retry", *args))

    def mark_indeterminate(self, *args):
        self.calls.append(("indeterminate", *args))

    def mark_dead_letter(self, *args):
        self.calls.append(("dead", *args))


class FakeExecutor:
    def __init__(self, result):
        self.result = result

    def execute(self, _action):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def worker(store, result, maximum_attempts=3):
    return DispatchWorker(
        store=store,
        executor=FakeExecutor(result),
        worker_id="worker-1",
        lease_seconds=60,
        maximum_attempts=maximum_attempts,
    )


class WorkerTests(unittest.TestCase):
    def test_delivers_claimed_action(self) -> None:
        store = FakeStore(ClaimedAction(action(), 1))
        self.assertTrue(worker(store, DispatchReceipt("request-1")).run_once())
        self.assertIn(("delivered", "event-4", "worker-1", "request-1"), store.calls)

    def test_retries_explicit_transient_failure_with_bounded_backoff(self) -> None:
        store = FakeStore(ClaimedAction(action(), 2))
        error = RetryableDispatchError("transient", "retry", 503)
        worker(store, error).run_once()
        self.assertIn(
            ("retry", "event-4", "worker-1", "transient", 503, 10), store.calls
        )

    def test_exhausted_retry_is_dead_lettered(self) -> None:
        store = FakeStore(ClaimedAction(action(), 3))
        worker(store, RetryableDispatchError("transient", "retry", 503)).run_once()
        self.assertIn(
            ("dead", "event-4", "worker-1", "retry_exhausted", 503), store.calls
        )

    def test_ambiguous_and_unexpected_failures_are_not_replayed(self) -> None:
        for error, code in (
            (IndeterminateDispatchError("ambiguous", "unknown"), "ambiguous"),
            (RuntimeError("unknown"), "unexpected_dispatch_failure"),
        ):
            store = FakeStore(ClaimedAction(action(), 1))
            worker(store, error).run_once()
            self.assertIn(
                ("indeterminate", "event-4", "worker-1", code, None), store.calls
            )

    def test_permanent_failure_is_dead_lettered(self) -> None:
        store = FakeStore(ClaimedAction(action(), 1))
        worker(store, PermanentDispatchError("rejected", "no", 403)).run_once()
        self.assertIn(("dead", "event-4", "worker-1", "rejected", 403), store.calls)


if __name__ == "__main__":
    unittest.main()
