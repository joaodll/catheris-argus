"""Where report files live on Docker Compose: a local volume the worker writes and the API reads
only (ADR-0047). The path check is the raw store's own: a key that resolves outside the root is
refused."""

import os
import re
from pathlib import Path
from uuid import uuid4

from argus.core.rawstore import FilesystemRawStore, RawRunError
from argus.reports.model import ReportFormat

FOLDER = "reports"
# The one shape a key may have; the table's CHECK holds the same pattern.
_KEY = re.compile(r"^reports/[0-9]+-[0-9a-f]{32}\.(csv|pdf)$")


class ReportStoreError(Exception):
    """A key that is not a report's, or a path outside the store."""


class LocalReportStore:
    def __init__(self, root: Path) -> None:
        self._files = FilesystemRawStore(root)

    def new_key(self, report_id: int, fmt: ReportFormat) -> str:
        return f"{FOLDER}/{report_id}-{uuid4().hex}.{fmt}"

    def path(self, key: str) -> Path:
        """The file of a key, checked twice: the key's shape, then that it stays in the root."""
        if not _KEY.fullmatch(key):
            raise ReportStoreError("not a report key")
        try:
            return self._files.open(key)
        except RawRunError as exc:  # the resolved path escapes the root
            raise ReportStoreError("report path escapes the store") from exc

    def temp_path(self, key: str) -> Path:
        """Where a build writes before the file is complete: beside the final file, hidden, so
        a rename publishes it whole."""
        final = self.path(key)
        final.parent.mkdir(mode=0o700, exist_ok=True)
        return final.with_name(f".{final.name}.part")

    def publish(self, temp: Path, key: str) -> None:
        target = self.path(key)
        with temp.open("rb") as f:
            os.fsync(f.fileno())
        os.replace(temp, target)

    def sweep(self, kept: set[str]) -> int:
        """Removes every file in the reports folder that no report names: a partial file a
        stopped build left, or one published just before its report could be recorded. Run
        only while nothing builds (the worker's report thread, as it starts). Returns how many
        files were removed."""
        folder = self._files.open(FOLDER)
        if not folder.is_dir():
            return 0
        removed = 0
        for entry in folder.iterdir():
            if f"{FOLDER}/{entry.name}" in kept or not entry.is_file() or entry.is_symlink():
                continue
            entry.unlink(missing_ok=True)
            removed += 1
        return removed

    def delete(self, key: str) -> bool:
        """Removes a file; False when it was already gone."""
        try:
            self.path(key).unlink()
        except FileNotFoundError:
            return False
        return True
