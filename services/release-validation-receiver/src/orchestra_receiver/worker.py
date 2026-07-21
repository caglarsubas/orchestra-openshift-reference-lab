from __future__ import annotations

import signal
import threading

from .config import WorkerConfig
from .errors import (
    IndeterminateDispatchError,
    PermanentDispatchError,
    RetryableDispatchError,
)
from .github import GitHubAppExecutor
from .store import PostgresStore


class DispatchWorker:
    def __init__(
        self,
        *,
        store: PostgresStore,
        executor: GitHubAppExecutor,
        worker_id: str,
        lease_seconds: int,
        maximum_attempts: int,
    ):
        self.store = store
        self.executor = executor
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.maximum_attempts = maximum_attempts

    def run_once(self) -> bool:
        claimed = self.store.claim_next(self.worker_id, self.lease_seconds)
        if not claimed:
            return False
        event_id = claimed.action.event_id
        try:
            receipt = self.executor.execute(claimed.action)
            self.store.mark_delivered(event_id, self.worker_id, receipt.request_id)
        except RetryableDispatchError as error:
            if claimed.attempt_count >= self.maximum_attempts:
                self.store.mark_dead_letter(
                    event_id, self.worker_id, "retry_exhausted", error.http_status
                )
            else:
                delay = min(300, 5 * (2 ** (claimed.attempt_count - 1)))
                self.store.mark_retry(
                    event_id, self.worker_id, error.code, error.http_status, delay
                )
        except IndeterminateDispatchError as error:
            self.store.mark_indeterminate(
                event_id, self.worker_id, error.code, error.http_status
            )
        except PermanentDispatchError as error:
            self.store.mark_dead_letter(
                event_id, self.worker_id, error.code, error.http_status
            )
        except Exception:
            self.store.mark_indeterminate(
                event_id, self.worker_id, "unexpected_dispatch_failure", None
            )
        return True


def main() -> None:
    config = WorkerConfig.from_env()
    store = PostgresStore(config.database_url)
    executor = GitHubAppExecutor(
        app_id=config.github_app_id,
        installation_id=config.github_installation_id,
        private_key_pem=config.github_private_key,
        repository_owner=config.github_repository_owner,
        repository_name=config.github_repository_name,
        api_url=config.github_api_url,
    )
    worker = DispatchWorker(
        store=store,
        executor=executor,
        worker_id=config.worker_id,
        lease_seconds=config.lease_seconds,
        maximum_attempts=config.maximum_attempts,
    )
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda _signum, _frame: stop.set())
    try:
        while not stop.is_set():
            if not worker.run_once():
                stop.wait(config.poll_milliseconds / 1000)
    finally:
        store.close()


if __name__ == "__main__":
    main()
