"""No secret printed by a tool reaches Postgres through its log tail or an error message."""

import dataclasses
from datetime import date
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import QUIET, RULES_DIR, make_demo

from argus.collection import CollectOptions, CollectTarget, FilesystemRawStore, collect, source_for
from argus.collection.collect import Outcome
from argus.core.manifest import Tool
from argus.ingest import ingest_run, register_run
from argus.scheduling import claims
from argus.settings import CollectionSettings

pytestmark = pytest.mark.db

DAY = date(2026, 9, 1)
# Fake values only, built at runtime so no scanner mistakes them for real credentials.
SECRETS = ("AKIA" + "Q" * 16, "pw-" + "x" * 12, "opaque-" + "y" * 10)
PRINTED = [
    f"assumed role with {SECRETS[0]}",
    f"DB_PASSWORD={SECRETS[1]}",
    f"│ lambda │ us-east-1 │ billing │ API_URL │ {SECRETS[2]} │",
]


class LeakySource:
    """The synthetic source, plus console output like CloudFox env-vars prints."""

    name = "synthetic"

    def collect(
        self,
        *,
        target: CollectTarget,
        tool: Tool,
        day: date,
        run_uid: UUID,
        out_dir: Path,
        options: CollectOptions,
    ) -> Outcome:
        outcome = source_for("demo").collect(
            target=target, tool=tool, day=day, run_uid=run_uid, out_dir=out_dir, options=options
        )
        return dataclasses.replace(outcome, log_lines=[*outcome.log_lines, *PRINTED])


def test_a_printed_secret_never_reaches_the_run_log(
    worker: Engine, owner: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    path, manifest = collect(
        LeakySource(),
        store,
        target=target,
        tool="cloudfox",
        day=DAY,
        run_uid=uuid4(),
        options=QUIET,
    )
    assert not any(secret in manifest.log_tail for secret in SECRETS)
    with worker.begin() as conn:
        scan_run_id = register_run(
            conn, connection_id=target.connection_id, raw_path=path, manifest=manifest
        )
    ingest_run(worker, store=store, scan_run_id=scan_run_id, rules_dir=RULES_DIR)
    with owner.connect() as conn:
        stored = conn.execute(
            text("SELECT log_tail FROM scan_run WHERE id = :i"), {"i": scan_run_id}
        ).scalar_one()
    assert "assumed role with" in stored  # the diagnostic line survives, minus the secret
    assert not any(secret in stored for secret in SECRETS)


def test_an_error_message_is_redacted_before_it_is_stored(owner: Engine) -> None:
    target = make_demo(owner)
    with owner.begin() as conn:
        request_id = conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, snapshot_date, "
                "requested_by) VALUES (:c, 'cloudfox', 'manual', :d, 'test') RETURNING id"
            ),
            {"c": target.connection_id, "d": DAY},
        ).scalar_one()
        claimed = claims.claim(conn, worker_id="test", settings=CollectionSettings())
        assert claimed is not None and claimed.id == request_id
        assert claims.finish(conn, claimed, scan_run_id=None, error="\n".join(PRINTED))
        error = conn.execute(
            text("SELECT error FROM run_request WHERE id = :i"), {"i": request_id}
        ).scalar_one()
    assert not any(secret in error for secret in SECRETS)
