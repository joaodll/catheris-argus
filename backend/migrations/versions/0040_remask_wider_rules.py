"""Stored configuration and text re-masked with the wider redaction rules (2026-11-05).

Revision ID: 0040
Revises: 0039
Create Date: 2026-11-05

`core.redaction` now reads more names as secret-bearing (pwd, apikey, dbpassword, Authorization,
connection_string and others) and masks more shapes inside text: headers, command lines, escaped
JSON, YAML blocks, and, in configuration, AWS key ids and PEM keys. `resource.tags` was also
stored from the raw row, without redaction.

This migration applies those rules to what is already stored: `resource_config.config`,
`resource.tags`, and the redacted text migration 0031 rewrote. Only values the rules now mask
change, and only rows that change are written.

As in migration 0028: a configuration keeps its `config_hash`, because the next scan of a resource
stores its configuration once more under the new hash and nothing compares the two. `audit_log` is
left as it is: it is append-only, and it never held tool output.

`edge.attributes` is left too. Rules and adapters choose what goes in it, read from a configuration
that was already redacted, and it holds facts under names like these rules': `credentials` lists
the kinds a user has (`access_key`), and CloudFox's `external_id` says whether one is required.

Every row of those tables is read in Python, in batches: the rules can't be written in SQL. The
writes are few, so this takes row locks on few rows.

Irreversible: a masked value cannot be restored, and the downgrade does nothing.
"""

import json
import re
from collections.abc import Callable, Iterator
from functools import lru_cache
from itertools import pairwise
from typing import Any

from alembic import op
from sqlalchemy import Connection, text

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

MASK = "********"
_BATCH = 2000
_TEXT = (
    ("finding", "detail"),
    ("scan_run", "log_tail"),
    ("scan_run", "command"),
    ("run_request", "error"),
    ("connection_test", "message"),
    ("finding_command", "command"),
    ("finding_command", "note"),
)
# A stored configuration doesn't say which table it came from, so every table's exception applies.
# Such a key was only ever stored in full by its own table.
_KEEP = frozenset(
    {
        "access_key_id",
        "access_key_last_used_date",
        "access_key_last_used_region",
        "access_key_last_used_service",
        "password_last_used",
        "encryption_key",
        "default_ebs_encryption_key",
        "volume_encryption_key",
    }
)

# ---------------------------------------------------------------- a copy of core.redaction
# As of this migration: a migration never imports application code, which keeps changing after it.
_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_SECRET_WORDS = frozenset({"environment", "variables"})
_SECRET_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "credential",
    "userdata",
    "apikey",
    "accesskey",
    "privatekey",
    "connectionstring",
    "sessionid",
)
_SECRET_PAIRS = frozenset(
    {
        ("user", "data"),
        ("private", "key"),
        ("api", "key"),
        ("access", "key"),
        ("external", "id"),
        ("connection", "string"),
        ("conn", "str"),
        ("session", "id"),
    }
)
_SECRET_LAST_WORDS = frozenset(
    {"authorization", "bearer", "cookie", "dsn", "pass", "sas", "signature", "webhook"}
)
_SECRET_LAST_PAIRS = frozenset(
    {
        ("client", "key"),
        ("encryption", "key"),
        ("license", "key"),
        ("master", "key"),
        ("session", "key"),
        ("shared", "key"),
        ("signing", "key"),
        ("ssh", "key"),
        ("webhook", "url"),
    }
)
_NOT_PASS = frozenset({"bypass", "compass", "encompass", "overpass", "underpass"})


def _secret_word(word: str) -> bool:
    if word == "secretsmanager":
        return False
    if word in _SECRET_WORDS or any(part in word for part in _SECRET_PARTS):
        return True
    return "token" in word and not word.endswith("tokens")


@lru_cache(maxsize=4096)
def is_secret_key(key: str) -> bool:
    words = [w.lower() for w in _WORD_RE.findall(key)]
    if not words:
        return False
    if any(_secret_word(w) for w in words) or any(p in _SECRET_PAIRS for p in pairwise(words)):
        return True
    last = words[-1]
    return (
        last in _SECRET_LAST_WORDS
        or (last.endswith("pass") and last not in _NOT_PASS)
        or tuple(words[-2:]) in _SECRET_LAST_PAIRS
    )


_URL_USERINFO_RE = re.compile(r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^\s/?#]*@)")
_URL_QUERY_RE = re.compile(r"(?P<lead>[?&;])(?P<name>[^\s=&#;?]+)=(?P<value>[^\s&#;]*)")
_URL_SECRET_PARAMS = frozenset(
    {"sig", "signature", "key", "apikey", "code", "auth", "authorization"}
)


def _url_secret_param(name: str) -> bool:
    lowered = name.lower()
    return (
        is_secret_key(name)
        or lowered in _URL_SECRET_PARAMS
        or lowered.rsplit("-", 1)[-1] in _URL_SECRET_PARAMS
    )


def _mask_query(match: re.Match[str]) -> str:
    if not match["value"] or not _url_secret_param(match["name"]):
        return match.group(0)
    return f"{match['lead']}{match['name']}={MASK}"


def _mask_url_credentials(value: str) -> str:
    if "://" not in value:
        return value
    value = _URL_USERINFO_RE.sub(lambda m: f"{m['scheme']}{MASK}@", value)
    return _URL_QUERY_RE.sub(_mask_query, value)


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value if value is None or value == "" else MASK


_PAIR_NAMES = (
    "Name",
    "name",
    "Key",
    "key",
    "ParameterKey",
    "parameterKey",
    "OutputKey",
    "OptionName",
)
_PAIR_VALUES = ("Value", "value", "ParameterValue", "parameterValue", "OutputValue")


def _secret_pair_value(document: dict[str, Any]) -> str | None:
    names = [document[k] for k in _PAIR_NAMES if isinstance(document.get(k), str)]
    if not any(is_secret_key(name) for name in names):
        return None
    return next((k for k in _PAIR_VALUES if k in document), None)


def redact(document: Any, *, keep: frozenset[str] = frozenset()) -> Any:
    if isinstance(document, dict):
        pair_value = _secret_pair_value(document)
        redacted: dict[str, Any] = {}
        for k, v in document.items():
            if k in keep:
                redacted[k] = v
            elif k == pair_value or is_secret_key(k):
                redacted[k] = _redact_value(v)
            else:
                redacted[k] = redact(v)
        return redacted
    if isinstance(document, list):
        return [redact(v) for v in document]
    if isinstance(document, str):
        return _redact_string(document)
    return document


def redact_tags(tags: dict[str, Any]) -> Any:
    return redact(tags, keep=frozenset(k for k in tags if k.lower() == "environment"))


def _redact_string(value: str) -> str:
    if value[:1] in ("{", "["):
        try:
            parsed = json.loads(value)
            masked = redact(parsed)
        except (ValueError, RecursionError):
            pass
        else:
            return value if masked == parsed else json.dumps(masked)
    masked_text = _mask_text(_mask_blocks(value))
    for pattern in _CONFIG_CREDENTIAL_RES:
        masked_text = pattern.sub(MASK, masked_text)
    return _MIXED_40_RE.sub(_mask_mixed_40, masked_text)


_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_PEM_LINE_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
)
_FORTY_RE = r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
_CREDENTIAL_RES = (_KEY_ID_RE, re.compile(_FORTY_RE), _JWT_RE, _PEM_LINE_RE)
_CONFIG_CREDENTIAL_RES = (_KEY_ID_RE, _JWT_RE)
_MIXED_40_RE = re.compile(_FORTY_RE)


def _mask_mixed_40(match: re.Match[str]) -> str:
    value = match.group(0)
    mixed = value not in (value.lower(), value.upper()) and not value.isalpha()
    return MASK if mixed else value


_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL
)
_YAML_BLOCK_RE = re.compile(
    r"""^(?P<head>(?P<indent>[ \t]*)(?:-[ \t]+)?["']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)["']?"""
    r"""[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\n)(?P<body>(?:(?P=indent)[ \t]+.*(?:\n|\Z)|[ \t]*\n)+)""",
    re.MULTILINE,
)


def _mask_yaml_block(match: re.Match[str]) -> str:
    if not is_secret_key(match["key"]):
        return match.group(0)
    end = "\n" if match["body"].endswith("\n") else ""
    return f"{match['head']}{match['indent']}  {MASK}{end}"


def _mask_blocks(value: str) -> str:
    if "-----BEGIN" in value:
        value = _PEM_BLOCK_RE.sub(MASK, value)
    return _YAML_BLOCK_RE.sub(_mask_yaml_block, value) if "\n" in value else value


_ASSIGNMENT_RE = re.compile(
    r"""(?P<key>"[A-Za-z_][A-Za-z0-9_.:-]*"|'[A-Za-z_][A-Za-z0-9_.:-]*'|["']?[A-Za-z_][A-Za-z0-9_.-]*["']?)"""
    r"""(?P<sep>\s*[:=]\s*)(?P<value>"[^"]*"|'[^']*'|\S+)"""
)
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def _mask_assignment(match: re.Match[str]) -> str:
    key = match["key"].strip("\"'")
    if is_secret_key(key) or _ENV_NAME_RE.fullmatch(key):
        return f"{match['key']}{match['sep']}{MASK}"
    if match["sep"] == ":":
        return match.group(0)
    value = _ASSIGNMENT_RE.sub(_mask_assignment, match["value"])
    return f"{match['key']}{match['sep']}{value}"


_FLAG_RE = re.compile(
    r"""(?P<flag>--[A-Za-z][A-Za-z0-9-]*)(?P<sep>[ \t]+)(?P<value>"[^"]*"|'[^']*'|[^\s"'-]\S*)"""
)


def _mask_flag(match: re.Match[str]) -> str:
    if is_secret_key(match["flag"][2:]):
        return f"{match['flag']}{match['sep']}{MASK}"
    return match.group(0)


_HEADER_RE = re.compile(
    r"""\b(?P<name>(?:proxy-)?authorization|(?:set-)?cookie)(?P<sep>["']?\s*[:=]\s*)"""
    r"""(?P<value>"[^"\n]*"|'[^'\n]*'|[^"'\n]*)""",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_ESCAPED_PAIR_RE = re.compile(
    r"""(?P<open>\\+")(?P<key>[A-Za-z_][A-Za-z0-9_.:-]*)(?P<mid>\\+"\s*:\s*\\+")"""
    r"""(?P<value>(?:[^"\\]|\\[^"])*)(?P<close>\\+")"""
)
_CLI_SECRET_RES = (
    re.compile(r"(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n|;&]*?\s-p)[^\s\"']\S*"),
    re.compile(r"(\bsshpass\s+-p\s*)\S+"),
    re.compile(r"(\bcurl\b[^\n|;&]*?\s(?:-u|--user)[ =]?)\S+"),
)
_AWS_CONFIGURE_RE = re.compile(r"(\baws\s+configure\s+set\s+(\S+)\s+)\S+")


def _mask_header(match: re.Match[str]) -> str:
    value = match["value"]
    if not value.strip():
        return match.group(0)
    quote = value[0] if value[0] in "\"'" else ""
    return f"{match['name']}{match['sep']}{quote}{MASK}{quote}"


def _mask_escaped_pair(match: re.Match[str]) -> str:
    if not is_secret_key(match["key"]):
        return match.group(0)
    return f"{match['open']}{match['key']}{match['mid']}{MASK}{match['close']}"


def _mask_aws_configure(match: re.Match[str]) -> str:
    return f"{match[1]}{MASK}" if is_secret_key(match[2]) else match.group(0)


def _mask_text(value: str) -> str:
    if '\\"' in value:
        value = _ESCAPED_PAIR_RE.sub(_mask_escaped_pair, value)
    lowered = value.lower()
    if "authorization" in lowered or "cookie" in lowered:
        value = _HEADER_RE.sub(_mask_header, value)
    if "bearer" in lowered:
        value = _BEARER_RE.sub(rf"\1{MASK}", value)
    if "configure" in lowered:
        value = _AWS_CONFIGURE_RE.sub(_mask_aws_configure, value)
    if " -" in value or "\t-" in value:
        for pattern in _CLI_SECRET_RES:
            value = pattern.sub(rf"\1{MASK}", value)
    return _FLAG_RE.sub(
        _mask_flag, _ASSIGNMENT_RE.sub(_mask_assignment, _mask_url_credentials(value))
    )


def _mask_line(line: str) -> str:
    for pattern in _CREDENTIAL_RES:
        line = pattern.sub(MASK, line)
    return _mask_text(line)


def remask_text(value: str) -> str:
    """Redacted text, once more. Table rows and encoded messages went at ingest: no new rule."""
    return "\n".join(_mask_line(line) for line in _mask_blocks(value).split("\n"))


# ---------------------------------------------------------------- what is stored


def _pages(conn: Connection, select: str, **params: Any) -> Iterator[list[Any]]:
    """Pages of a table by id. `select` holds :last and :n, and orders by id."""
    last = 0
    while True:
        rows = conn.execute(text(select), {**params, "last": last, "n": _BATCH}).all()
        if not rows:
            return
        yield rows
        last = rows[-1].id


def _documents(conn: Connection, table: str, column: str, masked: Callable[[Any], Any]) -> int:
    changed = 0
    select = f"SELECT id, {column} AS doc FROM {table} WHERE id > :last ORDER BY id LIMIT :n"  # noqa: S608
    for rows in _pages(conn, select):
        for row in rows:
            after = masked(row.doc)
            if after != row.doc:
                conn.execute(
                    text(f"UPDATE {table} SET {column} = CAST(:d AS jsonb) WHERE id = :id"),  # noqa: S608
                    {"d": json.dumps(after), "id": row.id},
                )
                changed += 1
    return changed


def _texts(conn: Connection, table: str, column: str) -> int:
    changed = 0
    select = (
        f"SELECT id, {column} AS value FROM {table} "  # noqa: S608 - fixed names
        f"WHERE id > :last AND {column} IS NOT NULL ORDER BY id LIMIT :n"
    )
    for rows in _pages(conn, select):
        for row in rows:
            masked = remask_text(row.value)
            if masked != row.value:
                conn.execute(
                    text(f"UPDATE {table} SET {column} = :v WHERE id = :id"),  # noqa: S608
                    {"v": masked, "id": row.id},
                )
                changed += 1
    return changed


def remask_stored(conn: Connection) -> int:
    """Returns how many values changed."""
    changed = _documents(conn, "resource_config", "config", lambda d: redact(d, keep=_KEEP))
    changed += _documents(conn, "resource", "tags", redact_tags)
    for table, column in _TEXT:
        changed += _texts(conn, table, column)
    return changed


def upgrade() -> None:
    remask_stored(op.get_bind())


def downgrade() -> None:
    """Nothing to undo: a masked value cannot be restored."""
