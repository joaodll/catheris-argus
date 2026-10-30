"""The Kubernetes API, for the scheduler only (ADR-0039, ADR-0040).

Two calls: create a Job from a fixed template, and list this release's Jobs. Standard library
only: the `kubernetes` package would bring a dozen dependencies into the one process that can
create pods, for two requests.

- The service-account token is read again on every call: Kubernetes rotates projected tokens.
- TLS is verified against the cluster CA the pod is given; there is no way to turn that off.
- An error carries the API's own Status message (an admission denial says what it refused),
  never the request body or headers.
"""

import http.client
import json
import os
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

SERVICE_ACCOUNT_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
PAGE = 200


class KubeError(Exception):
    """The API refused a request, or could not be reached."""

    def __init__(self, status: int, reason: str, message: str) -> None:
        super().__init__(f"{status} {reason}: {message}")
        self.status = status
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class JobState:
    name: str
    finished: bool  # a Complete or Failed condition is true
    ready: int = 0  # pods running and ready
    started_at: datetime | None = None  # when the Job controller started it


class _Response(Protocol):
    status: int
    reason: str

    def read(self, amt: int | None = None) -> bytes: ...


class _Connection(Protocol):
    def request(
        self, method: str, url: str, body: bytes | None = None, headers: dict[str, str] = ...
    ) -> None: ...
    def getresponse(self) -> _Response: ...
    def close(self) -> None: ...


Connect = Callable[[ssl.SSLContext], _Connection]


class KubeClient:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        sa_dir: Path = SERVICE_ACCOUNT_DIR,
        connect: Connect | None = None,
    ) -> None:
        self.sa_dir = sa_dir
        self.namespace = (sa_dir / "namespace").read_text().strip()
        self._connect = connect or (
            lambda context: http.client.HTTPSConnection(
                host, port, timeout=TIMEOUT_SECONDS, context=context
            )
        )

    @classmethod
    def in_cluster(cls) -> "KubeClient":
        """The API server Kubernetes gives every pod (its Service's address)."""
        try:
            host = os.environ["KUBERNETES_SERVICE_HOST"]
            port = int(os.environ["KUBERNETES_SERVICE_PORT"])
        except (KeyError, ValueError) as exc:
            raise KubeError(0, "NotInCluster", "the Kubernetes service address is not set") from exc
        return cls(host=host, port=port)

    def _request(self, method: str, path: str, body: bytes | None = None) -> dict[str, Any]:
        token = (self.sa_dir / "token").read_text().strip()
        context = ssl.create_default_context(cafile=str(self.sa_dir / "ca.crt"))
        conn = self._connect(context)
        try:
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            try:
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                data = response.read(MAX_RESPONSE_BYTES)
            except (OSError, http.client.HTTPException) as exc:
                raise KubeError(0, type(exc).__name__, "the Kubernetes API is unreachable") from exc
        finally:
            conn.close()
        try:
            payload: dict[str, Any] = json.loads(data) if data else {}
        except ValueError:
            payload = {}
        if not 200 <= response.status < 300:
            raise KubeError(
                response.status,
                str(payload.get("reason") or response.reason),
                str(payload.get("message") or "")[:1000],
            )
        return payload

    def create_job(self, body: bytes) -> str:
        """Submits a Job manifest as it is. Returns the name Kubernetes gave it."""
        created = self._request(
            "POST", f"/apis/batch/v1/namespaces/{quote(self.namespace)}/jobs", body
        )
        return str(created.get("metadata", {}).get("name", ""))

    def list_jobs(self, selector: str) -> list[JobState]:
        """This namespace's Jobs matching a label selector, every page."""
        jobs: list[JobState] = []
        token = ""
        while True:
            query = f"labelSelector={quote(selector)}&limit={PAGE}"
            if token:
                query += f"&continue={quote(token)}"
            page = self._request(
                "GET", f"/apis/batch/v1/namespaces/{quote(self.namespace)}/jobs?{query}"
            )
            for item in page.get("items", []):
                meta = item.get("metadata", {})
                conditions = item.get("status", {}).get("conditions") or []
                finished = any(
                    c.get("type") in ("Complete", "Failed") and c.get("status") == "True"
                    for c in conditions
                )
                status = item.get("status", {})
                jobs.append(
                    JobState(
                        str(meta.get("name", "")),
                        finished,
                        int(status.get("ready") or 0),
                        _timestamp(status.get("startTime")),
                    )
                )
            token = str(page.get("metadata", {}).get("continue") or "")
            if not token:
                return jobs


def _timestamp(value: object) -> datetime | None:
    """An RFC 3339 time from the API ("2026-10-24T18:00:00Z"), or None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
