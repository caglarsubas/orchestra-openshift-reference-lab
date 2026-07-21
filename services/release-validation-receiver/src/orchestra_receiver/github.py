from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .contracts import ReleaseAction
from .errors import (
    IndeterminateDispatchError,
    PermanentDispatchError,
    RetryableDispatchError,
)

_REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


@dataclass(frozen=True)
class DispatchReceipt:
    request_id: str | None


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class GitHubAppExecutor:
    def __init__(
        self,
        *,
        app_id: str,
        installation_id: str,
        private_key_pem: bytes,
        repository_owner: str,
        repository_name: str,
        api_url: str = "https://api.github.com",
        timeout_seconds: float = 10.0,
        now: Any = time.time,
        opener: Any = urllib.request.urlopen,
    ):
        if not app_id.isdigit() or not installation_id.isdigit():
            raise ValueError("GitHub App and installation ids must be numeric")
        for value in (repository_owner, repository_name):
            if not _REPOSITORY_COMPONENT.fullmatch(value):
                raise ValueError("GitHub repository identity is invalid")
        parsed_api_url = urlsplit(api_url)
        if (
            parsed_api_url.scheme != "https"
            or not parsed_api_url.hostname
            or parsed_api_url.username
            or parsed_api_url.password
            or parsed_api_url.query
            or parsed_api_url.fragment
        ):
            raise ValueError("GitHub API URL must be an HTTPS origin")
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError(
                "GitHub App key must be an RSA private key of at least 2048 bits"
            )
        self._app_id = app_id
        self._installation_id = installation_id
        self._key = key
        self._owner = repository_owner
        self._repository = repository_name
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout_seconds
        self._now = now
        self._opener = opener
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._token_lock = threading.Lock()

    def _jwt(self) -> str:
        issued_at = int(self._now()) - 60
        header = _base64url(
            json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode()
        )
        payload = _base64url(
            json.dumps(
                {"iat": issued_at, "exp": issued_at + 600, "iss": self._app_id},
                separators=(",", ":"),
            ).encode()
        )
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = self._key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{_base64url(signature)}"

    def _installation_token(self) -> str:
        with self._token_lock:
            if self._token and self._token_expires_at - self._now() > 60:
                return self._token
            request = urllib.request.Request(
                f"{self._api_url}/app/installations/{self._installation_id}/access_tokens",
                method="POST",
                data=b"{}",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._jwt()}",
                    "Content-Type": "application/json",
                    "User-Agent": "orchestra-reference-lab-receiver/0.1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            try:
                with self._opener(request, timeout=self._timeout) as response:
                    raw = response.read(32_768)
                    status = response.status
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
                if status == 429 or status >= 500:
                    raise RetryableDispatchError(
                        "github_token_transient",
                        "GitHub token endpoint is unavailable",
                        status,
                    ) from error
                raise PermanentDispatchError(
                    "github_token_rejected",
                    "GitHub App credentials were rejected",
                    status,
                ) from error
            except (TimeoutError, urllib.error.URLError) as error:
                raise RetryableDispatchError(
                    "github_token_unreachable", "GitHub token endpoint is unreachable"
                ) from error
            if status not in {200, 201}:
                raise PermanentDispatchError(
                    "github_token_unexpected",
                    "GitHub token endpoint returned an unexpected status",
                    status,
                )
            try:
                payload = json.loads(raw)
                token = payload["token"]
                expires_at = datetime.fromisoformat(
                    payload["expires_at"].replace("Z", "+00:00")
                ).timestamp()
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise PermanentDispatchError(
                    "github_token_contract", "GitHub token response is invalid"
                ) from error
            if not isinstance(token, str) or len(token) < 20:
                raise PermanentDispatchError(
                    "github_token_contract", "GitHub token is invalid"
                )
            if expires_at - self._now() <= 60:
                raise PermanentDispatchError(
                    "github_token_contract", "GitHub token is already expired"
                )
            self._token = token
            self._token_expires_at = expires_at
            return token

    def execute(self, action: ReleaseAction) -> DispatchReceipt:
        token = self._installation_token()
        body = json.dumps(
            {
                "event_type": "orchestra-release-validation",
                "client_payload": action.dispatch_payload(),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self._api_url}/repos/{self._owner}/{self._repository}/dispatches",
            method="POST",
            data=body,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "orchestra-reference-lab-receiver/0.1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self._opener(request, timeout=self._timeout) as response:
                response.read(1024)
                status = response.status
                request_id = response.headers.get("X-GitHub-Request-Id")
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if status == 429 or status >= 500:
                raise RetryableDispatchError(
                    "github_dispatch_transient",
                    "GitHub dispatch returned a retryable status",
                    status,
                ) from error
            raise PermanentDispatchError(
                "github_dispatch_rejected", "GitHub dispatch was rejected", status
            ) from error
        except (TimeoutError, urllib.error.URLError) as error:
            raise IndeterminateDispatchError(
                "github_dispatch_indeterminate",
                "GitHub dispatch outcome is unknown; automatic replay is blocked",
            ) from error
        if status != 204:
            raise PermanentDispatchError(
                "github_dispatch_unexpected",
                "GitHub dispatch returned an unexpected status",
                status,
            )
        return DispatchReceipt(request_id=request_id)
