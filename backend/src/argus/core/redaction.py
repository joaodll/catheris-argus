"""Secret redaction: the one definition of which values Argus never stores.

Every value under a secret-bearing key (Lambda environment variables, EC2 user data, anything
named like a credential) is replaced, keeping the shape: a dict of variables stays a dict, so
"a secret is present at X" survives while the value does not. A credential written inside a
URL (https://user:token@host, ?sig=...) is masked wherever the URL appears, whatever its key
(2026-10-09). Adapters apply this before anything reaches Postgres; the fixture scrubber
applies it before anything reaches git.
"""

import json
import re
from functools import lru_cache
from itertools import pairwise
from typing import Any

# What a secret becomes: a fixed-length mask, so neither a character nor the length of the value
# survives (the owner's choice, 2026-10-23, ADR-0024 amended). Before 2026-10-23 it was the word
# REDACTED; migration 0028 rewrote what was stored.
REDACTED = "********"
_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
# Single words that mark a secret-bearing key.
_SECRET_WORDS = frozenset({"environment", "variables"})
# Marks a key wherever a word holds it, so a name written without separators counts too:
# adminpassword, DBPASSWORD, secretkey, apikey.
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
# ("external", "id"): an ExternalId is not a secret to AWS, but Argus hides its own from the
# API (ADR-0024), and a scanned role's trust policy (sts:ExternalId) holds that same value.
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
# Secret only as the name's end: Authorization holds a credential, authorization_type says NONE or
# IAM, which the rules read. encryption_key holds a key, encryption_key_arn names one.
# HeaderValue: a CloudFront origin custom header ({"HeaderName", "HeaderValue"}) is the usual way
# an origin checks a request came through CloudFront, so its value is a shared secret whatever
# the header is called (X-Origin-Verify). The name stays (owner, 2026-11-05).
_SECRET_LAST_WORDS = frozenset(
    {"authorization", "bearer", "cookie", "dsn", "pass", "sas", "signature", "webhook"}
)
_SECRET_LAST_PAIRS = frozenset(
    {
        ("client", "key"),
        ("encryption", "key"),
        ("header", "value"),
        ("license", "key"),
        ("master", "key"),
        ("session", "key"),
        ("shared", "key"),
        ("signing", "key"),
        ("ssh", "key"),
        ("webhook", "url"),
    }
)
# Ordinary words that end like a password does (dbpass, adminpass).
_NOT_PASS = frozenset({"bypass", "compass", "encompass", "overpass", "underpass"})


def _secret_word(word: str) -> bool:
    if word == "secretsmanager":  # AWS's service prefix: secretsmanager:GetSecretValue in a policy
        return False
    if word in _SECRET_WORDS or any(part in word for part in _SECRET_PARTS):
        return True
    # "token" in any form but the plural: HttpTokens (IMDSv2 required/optional) is configuration,
    # SessionToken and authtoken are credentials.
    return "token" in word and not word.endswith("tokens")


@lru_cache(maxsize=4096)  # Scans repeat the same few names; a configuration holds many.
def is_secret_key(key: str) -> bool:
    """True for keys whose values can hold secrets: snake_case and camelCase are split into
    words, so SessionToken and user_data match while HttpTokens does not."""
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


# ---------------------------------------------------------------- credentials inside URLs
# A URL's userinfo (https://user:password@host) and the values of its credential-bearing query
# parameters. The key-based rule cannot see them: they sit under keys such as integration_uri,
# endpoint or url. The URL keeps its shape (scheme, host, path, parameter names), so a rule can
# still read the host. Parameter names beyond is_secret_key: signed and keyed URLs (S3
# presigned X-Amz-Signature, SAS sig, Google key, Azure Functions code).
# Userinfo runs to the last '@' before the path: a password holding a raw '@' is masked whole.
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
    return f"{match['lead']}{match['name']}={REDACTED}"


def mask_url_credentials(text: str) -> str:
    """Mask the credentials written inside URLs in a text: userinfo becomes ********@, and
    the value of a credential-bearing query parameter becomes ********. Only text that holds
    a URL is touched."""
    if "://" not in text:
        return text
    text = _URL_USERINFO_RE.sub(lambda m: f"{m['scheme']}{REDACTED}@", text)
    return _URL_QUERY_RE.sub(_mask_query, text)


def redact_value(value: Any) -> Any:
    """Keep the shape, destroy every leaf. An empty string holds nothing and stays empty, so
    "none is set" stays true (CloudFox's empty ExternalID column says a trust has none)."""
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value if value is None or value == "" else REDACTED


# Top-level Steampipe columns named like a secret that hold none: identifiers and dates an
# operator needs to judge a key or a user (decided 2026-10-07, argus_v7), and which KMS key
# encrypts a resource. Exact names, for one table each, at the top level of its rows only. Every
# nested key, every other table, and every other tool still goes through is_secret_key: a Lambda
# variable named access_key_id stays secret. The secret half of a key pair is not in these tables.
NOT_SECRET_COLUMNS: dict[str, frozenset[str]] = {
    "aws_iam_access_key": frozenset(
        {
            "access_key_id",
            "access_key_last_used_date",
            "access_key_last_used_region",
            "access_key_last_used_service",
        }
    ),
    "aws_iam_user": frozenset({"password_last_used"}),
    "aws_codeartifact_domain": frozenset({"encryption_key"}),
    "aws_codebuild_project": frozenset({"encryption_key"}),
    "aws_codepipeline_pipeline": frozenset({"encryption_key"}),
    "aws_ec2_regional_settings": frozenset({"default_ebs_encryption_key"}),
    "aws_workspaces_workspace": frozenset({"volume_encryption_key"}),
}


# A setting written as a name/value pair hides its name from the key-based rule:
# CloudFormation parameters [{"ParameterKey": "DbPassword", "ParameterValue": ...}], Elastic
# Beanstalk option settings [{"OptionName": "API_TOKEN", "Value": ...}], tag lists. When the
# name is secret-bearing, the value is redacted (argus_v8).
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
    """The key holding the value of a name/value pair whose name is secret-bearing."""
    names = [document[k] for k in _PAIR_NAMES if isinstance(document.get(k), str)]
    if not any(is_secret_key(name) for name in names):
        return None
    return next((k for k in _PAIR_VALUES if k in document), None)


def redact(document: Any, *, keep: frozenset[str] = frozenset()) -> Any:
    """Redact every value under a secret-bearing key, at any depth, and the value of every
    name/value pair whose name is secret-bearing. Text values are configuration written by
    people (an inline buildspec, a state machine definition, an event's input): a secret
    written inside one is masked too. `keep`: top-level keys of this document that look
    secret-bearing but are not (NOT_SECRET_COLUMNS), left as they are."""
    if isinstance(document, dict):
        pair_value = _secret_pair_value(document)
        redacted: dict[str, Any] = {}
        for k, v in document.items():
            if k in keep:
                redacted[k] = v
            elif k == pair_value or is_secret_key(k):
                redacted[k] = redact_value(v)
            else:
                redacted[k] = redact(v)
        return redacted
    if isinstance(document, list):
        return [redact(v) for v in document]
    if isinstance(document, str):
        return _redact_string(document)
    return document


def redact_tags(tags: dict[str, Any]) -> Any:
    """A resource's tags. "Environment" marks a map of variables in a configuration; as a tag's name
    it says prod or staging, and it is one of the commonest there are."""
    return redact(tags, keep=frozenset(k for k in tags if k.lower() == "environment"))


def _redact_string(text: str) -> str:
    """A configuration's text value. JSON inside a string is read as JSON, so a name/value pair or
    a string inside a string is seen too; unchanged, it keeps its exact text."""
    if text[:1] in ("{", "["):
        try:
            parsed = json.loads(text)
            masked = redact(parsed)
        except (ValueError, RecursionError):
            pass
        else:
            return text if masked == parsed else json.dumps(masked)
    masked_text = _mask_text(_mask_blocks(text))
    for pattern in _CONFIG_CREDENTIAL_RES:
        masked_text = pattern.sub(REDACTED, masked_text)
    return _MIXED_40_RE.sub(_mask_mixed_40, masked_text)


# ---------------------------------------------------------------- free text (run logs)
# A tool's console output is diagnostics, not data: the data is in its output files. Whatever
# of it reaches Postgres (a run's log tail, an error message) goes through redact_text first.
TABLE_ROW_OMITTED = "[table row omitted]"
# Tables print data (CloudFox env-vars prints every variable's value, whatever its name), so
# a line with three or more cells is dropped whole: box-drawing, pipe or tab separated.
_TABLE_ROW_RE = re.compile(r"(?:[│┃|].*){3,}|(?:\t.*){2,}")
# Credential shapes, wherever they appear: AWS key ids, 40-character AWS secret keys, JWTs,
# PEM blocks.
_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_PEM_LINE_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
)
_FORTY_RE = r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
_CREDENTIAL_RES = (_KEY_ID_RE, re.compile(_FORTY_RE), _JWT_RE, _PEM_LINE_RE)
# A configuration holds other text of that length: a commit is 40 hex digits, an IAM action 40
# letters. There only a mix of both cases with a digit, "/" or "+" counts as a secret key.
_CONFIG_CREDENTIAL_RES = (_KEY_ID_RE, _JWT_RE)
_MIXED_40_RE = re.compile(_FORTY_RE)


def _mask_mixed_40(match: re.Match[str]) -> str:
    value = match.group(0)
    mixed = value not in (value.lower(), value.upper()) and not value.isalpha()
    return REDACTED if mixed else value


# Values that span lines, seen only in the whole text: a PEM block, and a YAML block scalar under a
# secret key (password: |), whose value starts on the line after the key.
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
    return f"{match['head']}{match['indent']}  {REDACTED}{end}"


def _mask_blocks(text: str) -> str:
    if "-----BEGIN" in text:
        text = _PEM_BLOCK_RE.sub(REDACTED, text)
    return _YAML_BLOCK_RE.sub(_mask_yaml_block, text) if "\n" in text else text


# key=value, key: value, "key": "value". The value is masked when the key is secret-bearing
# (is_secret_key) or looks like an environment variable (UPPER_SNAKE), since any variable can
# hold a secret. A quoted key may hold a colon, so a namespaced JSON key is read whole
# ("sts:ExternalId": "x"; 2026-10-23). A bare key may not: an ARN ("...:secret:prod/db") is
# read from its start as arn: followed by the rest, and is never taken for an assignment.
_ASSIGNMENT_RE = re.compile(
    r"""(?P<key>"[A-Za-z_][A-Za-z0-9_.:-]*"|'[A-Za-z_][A-Za-z0-9_.:-]*'|["']?[A-Za-z_][A-Za-z0-9_.-]*["']?)"""
    r"""(?P<sep>\s*[:=]\s*)(?P<value>"[^"]*"|'[^']*'|\S+)"""
)
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def _mask_assignment(match: re.Match[str]) -> str:
    key = match["key"].strip("\"'")
    if is_secret_key(key) or _ENV_NAME_RE.fullmatch(key):
        return f"{match['key']}{match['sep']}{REDACTED}"
    # Not a secret key, but its value can hold an assignment of its own: in "ingest failed:
    # password=x" the first match is `failed` with the value `password=x` (2026-10-24, found in
    # the security review of round 3). Without this the scan went on after the value. A bare
    # colon is not read that way: inside an ARN ("arn:aws:...:secret:prod/db") it separates
    # the ARN's parts, not a key from its value.
    if match["sep"] == ":":
        return match.group(0)
    value = _ASSIGNMENT_RE.sub(_mask_assignment, match["value"])
    return f"{match['key']}{match['sep']}{value}"


# A command-line flag named like a secret, its value after a space (2026-10-23): --password x,
# --secret-access-key x, --external-id x. With "=" the assignment rule above has it. A value
# that starts with "-" is the next flag, not a value.
_FLAG_RE = re.compile(
    r"""(?P<flag>--[A-Za-z][A-Za-z0-9-]*)(?P<sep>[ \t]+)(?P<value>"[^"]*"|'[^']*'|[^\s"'-]\S*)"""
)


def _mask_flag(match: re.Match[str]) -> str:
    if is_secret_key(match["flag"][2:]):
        return f"{match['flag']}{match['sep']}{REDACTED}"
    return match.group(0)


# A header's value is the rest of it: "Authorization: Bearer x", "Cookie: a=1; b=2". Not
# authorization_type, whose name goes on, or prose, where no separator follows the word.
_HEADER_RE = re.compile(
    r"""\b(?P<name>(?:proxy-)?authorization|(?:set-)?cookie)(?P<sep>["']?\s*[:=]\s*)"""
    r"""(?P<value>"[^"\n]*"|'[^'\n]*'|[^"'\n]*)""",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
# A JSON key and value inside a string inside text: \"password\":\"x\".
_ESCAPED_PAIR_RE = re.compile(
    r"""(?P<open>\\+")(?P<key>[A-Za-z_][A-Za-z0-9_.:-]*)(?P<mid>\\+"\s*:\s*\\+")"""
    r"""(?P<value>(?:[^"\\]|\\[^"])*)(?P<close>\\+")"""
)
# Command lines that take a password in their own way.
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
    return f"{match['name']}{match['sep']}{quote}{REDACTED}{quote}"


def _mask_escaped_pair(match: re.Match[str]) -> str:
    if not is_secret_key(match["key"]):
        return match.group(0)
    return f"{match['open']}{match['key']}{match['mid']}{REDACTED}{match['close']}"


def _mask_aws_configure(match: re.Match[str]) -> str:
    return f"{match[1]}{REDACTED}" if is_secret_key(match[2]) else match.group(0)


def _mask_text(text: str) -> str:
    """A text value's secret assignments, secret flags, headers and URL credentials, masked."""
    # Each rule only where its word is: a configuration holds thousands of short strings.
    if '\\"' in text:
        text = _ESCAPED_PAIR_RE.sub(_mask_escaped_pair, text)
    lowered = text.lower()
    if "authorization" in lowered or "cookie" in lowered:
        text = _HEADER_RE.sub(_mask_header, text)
    if "bearer" in lowered:
        text = _BEARER_RE.sub(rf"\1{REDACTED}", text)
    if "configure" in lowered:
        text = _AWS_CONFIGURE_RE.sub(_mask_aws_configure, text)
    if " -" in text or "\t-" in text:
        for pattern in _CLI_SECRET_RES:
            text = pattern.sub(rf"\1{REDACTED}", text)
    return _FLAG_RE.sub(
        _mask_flag, _ASSIGNMENT_RE.sub(_mask_assignment, mask_url_credentials(text))
    )


# Terminal noise, removed before anything else: ANSI escape sequences (colours, cursor moves)
# and the C0 control characters other than tab and newline. PostgreSQL text cannot hold NUL, so
# one NUL in a tool's console output would stop its run being recorded at all.
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# AWS's encoded authorization failure message: kilobytes of opaque text that, decoded with
# sts:DecodeAuthorizationMessage, describe the request in full. The action it refers to is
# already named in plain text on the same line. A long unbroken run of base64url characters is
# the same blob cut by the log tail's start.
ENCODED_OMITTED = "[encoded message omitted]"
_ENCODED_RES = (
    re.compile(r"(Encoded authorization failure message:)\s*[A-Za-z0-9_-]+"),
    re.compile(r"[A-Za-z0-9_-]{100,}"),
)


def _clean(text: str) -> str:
    return _CONTROL_RE.sub("", _ANSI_RE.sub("", text))


def redact_line(line: str) -> str:
    if _TABLE_ROW_RE.search(line):
        return TABLE_ROW_OMITTED
    line = _ENCODED_RES[0].sub(rf"\1 {ENCODED_OMITTED}", line)
    line = _ENCODED_RES[1].sub(ENCODED_OMITTED, line)
    for pattern in _CREDENTIAL_RES:
        line = pattern.sub(REDACTED, line)
    return _mask_text(line)


def redact_text(text: str) -> str:
    """Redact free text line by line: table rows dropped, credential shapes and the values of
    secret-bearing or environment-style assignments masked. Terminal escapes and control
    characters are removed first."""
    return "\n".join(redact_line(line) for line in _mask_blocks(_clean(text)).split("\n"))
