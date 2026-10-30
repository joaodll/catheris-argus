"""Turn one real run of each tool into committable adapter fixtures (the Phase 0 spike).

Raw collector output identifies a real estate (account ids, resource names, emails, public
IPs) and can contain secret values (CloudFox env-vars). Fixtures go into git, so every such
value is replaced by a deterministic pseudonym before anything is written:

- One mapping is shared by all three tools, so a resource that Prowler, CloudFox and
  Steampipe all report keeps one identity, and resource_uid joins survive scrubbing.
- The mapping holds the original values. It stays in the spike directory, outside the repo,
  and is reused by later runs so pseudonyms are stable.
- After writing, a self-check searches the output for every original value and for secret
  patterns. Any hit deletes the output and fails the run.

Usage (inside the backend dev container, see `docker compose run --rm scrub-fixtures`):

    python tests/tooling/scrub_fixtures.py --spike-dir /spike --run-id ID [ID ...] \\
        --out tests/fixtures

Raw output has been gzip-compressed since 2026-10-08 (`<file>.gz` beside a plain
manifest.json): each file is read decompressed and written as a plain fixture under its name
without `.gz`, and the manifest's `raw_compression` is dropped, so a fixture reads as plain.

Each tool's run is found by its run id under raw/<tool>/aws/<account>/<YYYY>/<MM>/<DD>/ (or
an older run's raw/<tool>/aws/<account>/<YYYY-MM-DD>/). The worker gives
every run its own id, so pass the three ids (one per tool); one shared id also works.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import ipaddress
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from argus.core import redaction as core_redaction

TOOLS = ("prowler", "cloudfox", "steampipe")

ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
ARN_RE = re.compile(r"arn:aws[a-z-]*:([a-z0-9-]*):([a-z0-9-]*):(\d{12})?:([^\s\"',;\\|<>]+)")
AWS_ID_RE = re.compile(
    r"\b(i|sg|vpc|subnet|eni|vol|ami|snap|igw|nat|rtb|acl|lt|eipalloc|pcx|tgw|vpce|sgr|db|cluster)"
    r"-[0-9a-f]{8,17}\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Candidate IPv6 addresses; ipaddress decides which ones are real and global.
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
# RFC 5737 and RFC 3849 documentation ranges: never routable, obviously fake.
DOC_V4_NETS = ("192.0.2", "198.51.100", "203.0.113")
DOC_V4_CAPACITY = 254 * len(DOC_V4_NETS)

# IAM access key ids: identifiers, kept (pseudonymised) in the IAM tables (NOT_SECRET_COLUMNS).
# The pseudonym has no credential shape, so the secret scan never mistakes it for one.
KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")

# Secret shapes that must never survive, whatever file they are in.
SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # Not after ":" or "/", so an ARN's "secret:<name>" (Secrets Manager) is a name, not a value;
    # the value ends at whitespace or a quote, so compact JSON around it stays parseable, and a
    # value with a comma or semicolon in it is still taken whole.
    re.compile(
        r"(?i)(?<![:/])\b(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s\"']{6,}"
    ),
)

# Names that are AWS conventions rather than facts about this estate. Kept, so fixtures still
# exercise the logic that depends on them (default VPCs, service-linked roles).
KEEP_NAMES = frozenset({"*", "root", "default", "service-role", "aws-service-role", "accesskey"})
MIN_NAME_LEN = 3


def _is_kept_name(name: str) -> bool:
    return (
        name in KEEP_NAMES or name.startswith(("AWS", "aws-", "Amazon")) or len(name) < MIN_NAME_LEN
    )


def _name_pattern(name: str) -> re.Pattern[str]:
    # A name matches only as a whole token, so "prod" never rewrites part of "production".
    return re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])")


# Keys whose values are free text an organisation chooses (tags). Every string under them is
# pseudonymised even though it never appears in an ARN.
TAG_KEYS = frozenset({"tags", "tags_src", "Tags", "resource_tags", "ResourceTags"})

# The one definition of secret-bearing keys lives with the adapters' redaction.
is_secret_key = core_redaction.is_secret_key

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


def _strings(value: JsonValue) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


def _redact(value: JsonValue) -> JsonValue:
    """Keep the shape (so adapters still see a dict of variables), destroy every value."""
    redacted: JsonValue = core_redaction.redact_value(value)
    return redacted


def _tag_values(value: JsonValue) -> list[str]:
    """Every string nested under a tag key, at any depth."""
    if isinstance(value, list):
        return [s for v in value for s in _tag_values(v)]
    if isinstance(value, dict):
        found: list[str] = []
        for key, v in value.items():
            found += _strings(v) if key in TAG_KEYS else _tag_values(v)
        return found
    return []


@dataclass
class Mapping:
    accounts: dict[str, str] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)
    ids: dict[str, str] = field(default_factory=dict)
    emails: dict[str, str] = field(default_factory=dict)
    ips: dict[str, str] = field(default_factory=dict)
    keys: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> Mapping:
        if not path.exists():
            return cls()
        return cls(**json.loads(path.read_text()))

    def save(self, path: Path) -> None:
        # Created owner-only from the first byte: it holds every original value.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(self.__dict__, indent=2, sort_keys=True))
        path.chmod(0o600)

    def originals(self) -> list[str]:
        return [*self.accounts, *self.names, *self.ids, *self.emails, *self.ips, *self.keys]

    def account(self, value: str) -> str:
        return self.accounts.setdefault(value, f"{100000000000 + len(self.accounts) + 1}")

    def name(self, value: str, kind: str) -> str:
        return self.names.setdefault(value, f"{kind}-{len(self.names) + 1:04d}")

    def aws_id(self, value: str) -> str:
        prefix = value.rsplit("-", 1)[0]
        width = len(value) - len(prefix) - 1
        return self.ids.setdefault(value, f"{prefix}-{len(self.ids) + 1:0{width}x}")

    def key_id(self, value: str) -> str:
        return self.keys.setdefault(value, f"FIXTUREKEY{len(self.keys) + 1:010d}")

    def email(self, value: str) -> str:
        return self.emails.setdefault(value, f"user-{len(self.emails) + 1:04d}@example.com")

    def ip(self, value: str) -> str:
        if value in self.ips:
            return self.ips[value]
        n = len(self.ips)
        if ":" in value:
            pseudonym = f"2001:db8::{n + 1:x}"
        elif n < DOC_V4_CAPACITY:
            pseudonym = f"{DOC_V4_NETS[n // 254]}.{n % 254 + 1}"
        else:
            raise SystemExit(
                "more public IPv4 addresses than documentation ranges can pseudonymise"
            )
        self.ips[value] = pseudonym
        return pseudonym


class Scrubber:
    def __init__(self, mapping: Mapping) -> None:
        self.m = mapping
        self._names_re: re.Pattern[str] | None = None
        self._names_count = -1

    # Pass 1: learn every name that appears inside an ARN, in every file of every tool, so
    # the same name is replaced wherever it appears later, including outside ARNs.
    def learn(self, text: str) -> None:
        for service, _region, _account, resource in ARN_RE.findall(text):
            segments = re.split(r"[/:]", resource)
            if len(segments) == 1:
                kind = "bucket" if service == "s3" else service or "name"
                names = segments
            else:
                kind, names = segments[0] or service, segments[1:]
            for name in names:
                # AWS ids and account ids keep their own shape-preserving pseudonyms (i-…,
                # sg-…), so resolver rules that parse them see realistic ids in fixtures.
                if AWS_ID_RE.fullmatch(name) or ACCOUNT_RE.fullmatch(name):
                    continue
                if KEY_ID_RE.fullmatch(name):  # pseudonymised as a key id, not a name
                    continue
                if name and not _is_kept_name(name):
                    self.m.name(name, kind)

    def learn_tags(self, document: JsonValue) -> None:
        for value in _tag_values(document):
            if not _is_kept_name(value):
                self.m.name(value, "tag")

    def _names_pattern(self) -> re.Pattern[str] | None:
        """One alternation of every learned name, longest first, rebuilt only when names grow.

        A pattern per name would rescan every string once per name; at estate size that is
        millions of strings times thousands of names.
        """
        if len(self.m.names) != self._names_count:
            self._names_count = len(self.m.names)
            names = sorted(self.m.names, key=len, reverse=True)
            alternation = "|".join(map(re.escape, names))
            self._names_re = (
                re.compile(rf"(?<![A-Za-z0-9_-])(?:{alternation})(?![A-Za-z0-9_-])")
                if names
                else None
            )
        return self._names_re

    # Pass 2: rewrite.
    def scrub_json(self, value: JsonValue, keep: frozenset[str] = frozenset()) -> JsonValue:
        """Rewrite values only; keys are structure and stay as they are. `keep`: top-level keys
        named like a secret that hold none (core.redaction.NOT_SECRET_COLUMNS)."""
        if isinstance(value, dict):
            return {
                k: _redact(v) if is_secret_key(k) and k not in keep else self.scrub_json(v)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.scrub_json(v) for v in value]
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, int) and not isinstance(value, bool):
            text = str(value)
            return int(self.m.account(text)) if ACCOUNT_RE.fullmatch(text) else value
        return value

    def scrub_csv(self, text: str) -> str:
        """Rewrite data cells; the header row is structure and stays as it is."""
        rows = list(csv.reader(io.StringIO(text)))
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        for i, row in enumerate(rows):
            writer.writerow(row if i == 0 else [self.scrub_text(cell) for cell in row])
        return out.getvalue()

    def scrub_file(self, rel: Path, text: str) -> str:
        if rel.suffix == ".json":
            return json.dumps(self.scrub_json(json.loads(text)), indent=1) + "\n"
        if rel.suffix == ".jsonl":
            keep = _not_secret(rel)
            lines = [
                json.dumps(self.scrub_json(json.loads(line), keep))
                for line in text.splitlines()
                if line
            ]
            return "\n".join(lines) + ("\n" if lines else "")
        if rel.suffix == ".csv":
            return self.scrub_csv(text)
        return self.scrub_text(text)

    def scrub_text(self, text: str) -> str:
        text = core_redaction.mask_url_credentials(text)
        names_re = self._names_pattern()
        if names_re is not None:
            text = names_re.sub(lambda mt: self.m.names[mt.group(0)], text)
        text = ACCOUNT_RE.sub(lambda mt: self.m.account(mt.group(0)), text)
        text = AWS_ID_RE.sub(lambda mt: self.m.aws_id(mt.group(0)), text)
        text = KEY_ID_RE.sub(lambda mt: self.m.key_id(mt.group(0)), text)
        text = EMAIL_RE.sub(lambda mt: self.m.email(mt.group(0)), text)
        text = IPV4_RE.sub(self._scrub_ip, text)
        text = IPV6_RE.sub(self._scrub_ip, text)
        for pattern in SECRET_PATTERNS:
            text = pattern.sub(core_redaction.REDACTED, text)
        return text

    def _scrub_ip(self, match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value
        # Private and special ranges carry topology, not identity; relationship rules need them.
        return self.m.ip(value) if address.is_global else value

    def scrub_env_vars_csv(self, text: str) -> str:
        """CloudFox env-vars prints secret values. Blank the value column before anything else."""
        rows = list(csv.reader(io.StringIO(text)))
        if not rows:
            return text
        header = [h.strip().lower() for h in rows[0]]
        if "value" not in header:
            raise ValueError("env-vars CSV without a Value column: format changed, refusing")
        col = header.index("value")
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(rows[0])
        for row in rows[1:]:
            if len(row) > col:
                row[col] = core_redaction.REDACTED
            writer.writerow(row)
        return out.getvalue()


def _is_env_vars(path: Path) -> bool:
    return "env-vars" in path.as_posix() or "env_vars" in path.as_posix()


# CloudFox 2.0.5 loot that holds secret values in free text (docs/spikes/cloudfox-loot.md,
# 2026-10-14): an instance's user data in full, and stack parameters and outputs. Dropped
# whole, like env-vars free text: no pattern is trusted to find every secret in them.
_SECRET_LOOT = frozenset({"instance-userdata.txt", "cloudformation-data.txt"})


def _is_secret_loot(path: Path) -> bool:
    return path.name in _SECRET_LOOT


def _read_text(path: Path) -> str | None:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as packed:
                return packed.read()
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, gzip.BadGzipFile):
        return None


def _plain_manifest(text: str) -> str:
    """The manifest of a compressed run, as one whose files are plain (the fixtures are)."""
    manifest = json.loads(text)
    manifest.pop("raw_compression", None)
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def _documents(rel: Path, text: str) -> list[JsonValue]:
    if rel.suffix == ".json":
        return [json.loads(text)]
    if rel.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line]
    return []


def find_runs(spike_dir: Path, run_ids: str | list[str]) -> dict[str, Path]:
    ids = [run_ids] if isinstance(run_ids, str) else run_ids
    runs: dict[str, Path] = {}
    for tool in TOOLS:
        matches = sorted(
            m
            for run_id in ids
            # aws/<account>/<YYYY>/<MM>/<DD>/<run id>, or <YYYY-MM-DD>/ before 2026-10-06
            for pattern in (f"aws/*/*/*/*/{run_id}", f"aws/*/*/{run_id}")
            for m in (spike_dir / "raw" / tool).glob(pattern)
        )
        if len(matches) != 1:
            raise SystemExit(
                f"{tool}: expected one run directory among {ids}, found {len(matches)}"
            )
        runs[tool] = matches[0]
    return runs


def _keys(value: JsonValue) -> list[str]:
    if isinstance(value, list):
        return [k for v in value for k in _keys(v)]
    if isinstance(value, dict):
        return [k for key, v in value.items() for k in (key, *_keys(v))]
    return []


def _found(text: str, originals: list[str]) -> list[str]:
    found = [o for o in originals if len(o) >= MIN_NAME_LEN and _name_pattern(o).search(text)]
    found += [p.pattern for p in SECRET_PATTERNS if p.search(text)]
    return found


def leaks(dest: Path, text: str, mapping: Mapping) -> list[str]:
    """Original values left in the output.

    JSON keys are tool schema and are kept on purpose, so a resource named like a key
    ("status") is not a leak there. Keys are still checked for every original that is not a
    name: account ids, AWS ids, emails and IPs never belong in a key.
    """
    everything = mapping.originals()
    found = _found(dest.as_posix(), everything)
    documents = _documents(dest, text)
    if not documents:
        return found + _found(text, everything)
    not_names = [*mapping.accounts, *mapping.ids, *mapping.emails, *mapping.ips, *mapping.keys]
    keep = _not_secret(dest)
    for document in documents:
        found += [
            f"unredacted value under secret key {k!r}"
            for k in _unredacted_secret_keys(document, keep)
        ]
        found += _found("\n".join(_strings(document)), everything)
        found += _found("\n".join(map(str, _numbers(document))), list(mapping.accounts))
        found += _found("\n".join(_keys(document)), not_names)
    return found


def _not_secret(path: Path) -> frozenset[str]:
    """The top-level keys of a Steampipe table's rows that are not secret although named so."""
    if path.suffix != ".jsonl":
        return frozenset()
    return core_redaction.NOT_SECRET_COLUMNS.get(path.stem, frozenset())


def _unredacted_secret_keys(value: JsonValue, keep: frozenset[str] = frozenset()) -> list[str]:
    if isinstance(value, list):
        return [k for v in value for k in _unredacted_secret_keys(v)]
    if isinstance(value, dict):
        found: list[str] = []
        for key, v in value.items():
            if is_secret_key(key) and key not in keep:
                if any(s not in (core_redaction.REDACTED, "") for s in _strings(v)) or _numbers(v):
                    found.append(key)
            else:
                found += _unredacted_secret_keys(v)
        return found
    return []


def _numbers(value: JsonValue) -> list[int | float]:
    if isinstance(value, bool):
        return []
    if isinstance(value, int | float):
        return [value]
    if isinstance(value, list):
        return [n for v in value for n in _numbers(v)]
    if isinstance(value, dict):
        return [n for v in value.values() for n in _numbers(v)]
    return []


RawFile = tuple[str, Path, Path, str]


def _collect_files(runs: dict[str, Path]) -> tuple[list[RawFile], list[str]]:
    """Every text file of every tool's run, plus the files deliberately left out."""
    files: list[RawFile] = []
    dropped: list[str] = []
    for tool, run_dir in runs.items():
        for path in sorted(run_dir.rglob("*")):
            rel = path.relative_to(run_dir)
            if path.is_symlink():
                # Raw output is written by third-party tools; a link could point anywhere.
                raise SystemExit(f"{tool}/{rel}: symlink in raw output, refusing")
            if not path.is_file():
                continue
            text = _read_text(path)
            if text is None:
                dropped.append(f"{tool}/{rel} (binary)")
                continue
            if rel.suffix == ".gz":
                rel = rel.with_suffix("")
            elif rel.name == "manifest.json":
                text = _plain_manifest(text)
            if _is_secret_loot(rel):
                dropped.append(f"{tool}/{rel} (secret values in free text)")
                continue
            if _is_env_vars(rel) and path.suffix != ".csv":
                # Only the CSV has a column we can blank reliably; tables and loot files are
                # free text, so they are dropped rather than trusted to a pattern.
                dropped.append(f"{tool}/{rel} (env-vars free text)")
                continue
            files.append((tool, rel, path, text))
    return files, dropped


def scrub_run(spike_dir: Path, run_id: str | list[str], out_dir: Path) -> list[str]:
    """Scrub one run into out_dir/<tool>/. Returns the files dropped instead of scrubbed."""
    mapping_path = spike_dir / "scrub-mapping.json"
    mapping = Mapping.load(mapping_path)
    scrubber = Scrubber(mapping)
    runs = find_runs(spike_dir, run_id)

    files, dropped = _collect_files(runs)

    for tool, rel, _path, text in files:
        scrubber.learn(text)
        scrubber.learn(rel.as_posix())
        try:
            documents = _documents(rel, text)
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"{tool}/{rel}: not valid JSON ({exc.msg}). Fixtures come from complete runs only; "
                "check the run log and timings for a failed tool."
            ) from None
        for document in documents:
            scrubber.learn_tags(document)

    staged: dict[Path, str] = {}
    for tool, rel, _path, raw in files:
        # Secret values are blanked first, so they never reach the general rewrite.
        text = scrubber.scrub_env_vars_csv(raw) if _is_env_vars(rel) else raw
        dest = out_dir / tool / scrubber.scrub_text(rel.as_posix())
        staged[dest] = scrubber.scrub_file(rel, text)

    problems = [
        f"{dest}: {hit}" for dest, text in staged.items() for hit in leaks(dest, text, mapping)
    ]
    if problems:
        raise SystemExit(
            "refusing to write, original values survived scrubbing:\n" + "\n".join(problems)
        )

    for tool in TOOLS:
        shutil.rmtree(out_dir / tool, ignore_errors=True)
    for dest, text in staged.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    mapping.save(mapping_path)
    return dropped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--spike-dir", type=Path, required=True)
    parser.add_argument("--run-id", nargs="+", required=True, help="one per tool, or one shared")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    dropped = scrub_run(args.spike_dir, args.run_id, args.out)
    for item in dropped:
        print(f"dropped: {item}")
    print(f"fixtures written to {args.out}; review `git diff --stat` before committing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
