"""The scheduler's Kubernetes client: the token is read on every call, TLS is always verified,
and an error says what the API said, never what was sent."""

import json
import ssl
from datetime import UTC, datetime
from pathlib import Path

import pytest

from argus.core.kube import KubeClient, KubeError

TOKEN = "fixture-token-not-a-real-one"


class _Response:
    def __init__(self, status: int, payload: object, reason: str = "") -> None:
        self.status = status
        self.reason = reason
        self._data = json.dumps(payload).encode()

    def read(self, amt: int | None = None) -> bytes:
        return self._data


class _Fake:
    """An HTTPSConnection that records requests and answers from a queue."""

    def __init__(self, answers: list[_Response]) -> None:
        self.answers = answers
        self.requests: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.contexts: list[ssl.SSLContext] = []

    def __call__(self, context: ssl.SSLContext) -> "_Fake":
        self.contexts.append(context)
        return self

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.requests.append((method, url, body, dict(headers or {})))

    def getresponse(self) -> _Response:
        return self.answers.pop(0)

    def close(self) -> None:
        pass


@pytest.fixture
def sa_dir(tmp_path: Path) -> Path:
    (tmp_path / "token").write_text(TOKEN + "-1")
    (tmp_path / "namespace").write_text("argus\n")
    (tmp_path / "ca.crt").write_text("")  # the fake connection never reads it
    return tmp_path


def _client(sa_dir: Path, fake: _Fake, monkeypatch: pytest.MonkeyPatch) -> KubeClient:
    contexts: list[str] = []
    default_context = ssl.create_default_context

    def verified(*, cafile: str) -> ssl.SSLContext:
        contexts.append(cafile)  # the cluster CA; the real context would load it
        return default_context()

    monkeypatch.setattr("argus.core.kube.ssl.create_default_context", verified)
    client = KubeClient(host="10.96.0.1", port=443, sa_dir=sa_dir, connect=fake)
    client.cafiles = contexts  # type: ignore[attr-defined]
    return client


def test_create_job_posts_the_template_as_it_is_with_a_fresh_token(
    sa_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _Fake([_Response(201, {"metadata": {"name": "argus-run-aws-x1"}})] * 2)
    client = _client(sa_dir, fake, monkeypatch)
    body = b'{"kind": "Job"}'
    assert client.create_job(body) == "argus-run-aws-x1"
    (sa_dir / "token").write_text(TOKEN + "-2")  # rotated
    client.create_job(body)
    (m1, url, sent, h1), (_, _, _, h2) = fake.requests
    assert (m1, url, sent) == ("POST", "/apis/batch/v1/namespaces/argus/jobs", body)
    assert h1["Authorization"] == f"Bearer {TOKEN}-1"
    assert h2["Authorization"] == f"Bearer {TOKEN}-2"
    assert client.cafiles == [str(sa_dir / "ca.crt")] * 2  # type: ignore[attr-defined]
    ctx = fake.contexts[0]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_a_denial_carries_the_api_message_only(
    sa_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    denial = {"kind": "Status", "reason": "Invalid", "message": "denied by argus-run-jobs: image"}
    fake = _Fake([_Response(422, denial, "Unprocessable Entity")])
    client = _client(sa_dir, fake, monkeypatch)
    with pytest.raises(KubeError) as raised:
        client.create_job(b'{"spec": "secret-looking-body"}')
    assert raised.value.status == 422 and raised.value.reason == "Invalid"
    assert "denied by argus-run-jobs" in str(raised.value)
    assert "secret-looking-body" not in str(raised.value) and TOKEN not in str(raised.value)


def test_an_unreachable_api_is_a_kube_error(sa_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Down(_Fake):
        def getresponse(self) -> _Response:
            raise ConnectionRefusedError("refused")

    client = _client(sa_dir, _Down([]), monkeypatch)
    with pytest.raises(KubeError, match="unreachable"):
        client.list_jobs("app=argus")


def test_list_jobs_reads_every_page_and_which_are_finished(
    sa_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def job(name: str, condition: str | None) -> dict[str, object]:
        conditions = [{"type": condition, "status": "True"}] if condition else []
        return {
            "metadata": {"name": name, "labels": {"app.kubernetes.io/component": "run"}},
            "status": {
                "conditions": conditions,
                "ready": 1,
                "startTime": "2026-10-24T18:00:00Z",
            },
        }

    fake = _Fake(
        [
            _Response(200, {"items": [job("a", None)], "metadata": {"continue": "p2"}}),
            _Response(200, {"items": [job("b", "Complete"), job("c", "Failed")]}),
        ]
    )
    client = _client(sa_dir, fake, monkeypatch)
    jobs = client.list_jobs("app.kubernetes.io/component=run")
    assert [(j.name, j.finished) for j in jobs] == [("a", False), ("b", True), ("c", True)]
    assert jobs[0].ready == 1
    assert jobs[0].started_at == datetime(2026, 10, 24, 18, tzinfo=UTC)
    assert "labelSelector=app.kubernetes.io/component%3Drun" in fake.requests[0][1]
    assert "continue=p2" in fake.requests[1][1]


def test_outside_a_cluster_there_is_no_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    with pytest.raises(KubeError, match="not set"):
        KubeClient.in_cluster()
