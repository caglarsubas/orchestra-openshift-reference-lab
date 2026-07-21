from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .signing import load_signing_secrets


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value or value.strip() != value:
        raise RuntimeError(f"{name} is required")
    return value


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer") from error
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def read_secret_file(path: str, *, maximum_bytes: int = 262_144) -> bytes:
    target = Path(path)
    # Kubernetes projected Secret files are symlinks into the volume's ..data tree.
    if not target.is_file() or not target.resolve(strict=True).is_file():
        raise RuntimeError(f"secret path is not a regular file: {path}")
    raw = target.read_bytes()
    if not raw or len(raw) > maximum_bytes:
        raise RuntimeError(f"secret file has invalid size: {path}")
    return raw.rstrip(b"\r\n")


def database_url_from_env() -> str:
    path = os.environ.get("RECEIVER_DATABASE_URL_FILE")
    if path:
        return read_secret_file(path, maximum_bytes=8192).decode("utf-8")
    return _required("RECEIVER_DATABASE_URL")


@dataclass(frozen=True)
class ApiConfig:
    database_url: str
    signing_secrets: tuple[bytes, ...]
    admin_token: bytes
    signature_tolerance_seconds: int
    maximum_body_bytes: int

    @classmethod
    def from_env(cls) -> "ApiConfig":
        return cls(
            database_url=database_url_from_env(),
            signing_secrets=load_signing_secrets(
                read_secret_file(
                    _required("RECEIVER_WEBHOOK_SECRETS_FILE"), maximum_bytes=8192
                )
            ),
            admin_token=read_secret_file(
                _required("RECEIVER_ADMIN_TOKEN_FILE"), maximum_bytes=8192
            ),
            signature_tolerance_seconds=_bounded_int(
                "RECEIVER_SIGNATURE_TOLERANCE_SECONDS", 300, 30, 900
            ),
            maximum_body_bytes=_bounded_int(
                "RECEIVER_MAXIMUM_BODY_BYTES", 262_144, 1024, 1_048_576
            ),
        )


@dataclass(frozen=True)
class WorkerConfig:
    database_url: str
    worker_id: str
    lease_seconds: int
    poll_milliseconds: int
    maximum_attempts: int
    github_app_id: str
    github_installation_id: str
    github_private_key: bytes
    github_repository_owner: str
    github_repository_name: str
    github_api_url: str

    @classmethod
    def from_env(cls) -> "WorkerConfig":
        return cls(
            database_url=database_url_from_env(),
            worker_id=_required("RECEIVER_WORKER_ID"),
            lease_seconds=_bounded_int("RECEIVER_WORKER_LEASE_SECONDS", 60, 15, 600),
            poll_milliseconds=_bounded_int(
                "RECEIVER_WORKER_POLL_MILLISECONDS", 1000, 100, 60_000
            ),
            maximum_attempts=_bounded_int("RECEIVER_WORKER_MAXIMUM_ATTEMPTS", 8, 1, 32),
            github_app_id=_required("RECEIVER_GITHUB_APP_ID"),
            github_installation_id=_required("RECEIVER_GITHUB_INSTALLATION_ID"),
            github_private_key=read_secret_file(
                _required("RECEIVER_GITHUB_PRIVATE_KEY_FILE")
            ),
            github_repository_owner=_required("RECEIVER_GITHUB_REPOSITORY_OWNER"),
            github_repository_name=_required("RECEIVER_GITHUB_REPOSITORY_NAME"),
            github_api_url=os.environ.get(
                "RECEIVER_GITHUB_API_URL", "https://api.github.com"
            ),
        )
