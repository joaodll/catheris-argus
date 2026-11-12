"""SAML sign-in (ADR-0048): SP-initiated, configured in the deployment, ending in the same session
as a password sign-in.

This side never reads the IdP's XML. saml_check.py does, in a child process with an empty
environment (run_isolated), at most CHECKS_AT_ONCE at a time. This side keeps the state, the
database and the session:

- start(): asks the child for an AuthnRequest and signs the state the answer must match (request id,
  where to go next, expiry) into a cookie. Nothing is written: an unauthenticated route can't grow
  the database (review A1).
- finish(): checks the state cookie, has the child check the answer, refuses a replayed assertion,
  finds or creates the user from the groups, and starts the session.

Every refusal is a fixed code, shown on the sign-in page as `sso-<code>` and audited once per
address and code per window. Nothing the IdP wrote is shown or stored.
"""

import base64
import hashlib
import hmac
import json
import secrets
import sys
import threading
import time
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

from sqlalchemy import Connection, text

from argus.auth import users
from argus.auth.sessions import ROLES, Role, start_session
from argus.core import audit
from argus.core.config import get_settings
from argus.core.process import IsolatedRunError, run_isolated
from argus.core.secrets import derived_key

ACS_PATH = "/api/v1/auth/saml/acs"
METADATA_PATH = "/api/v1/auth/saml/metadata"
STATE_COOKIE = "argus_saml"
STATE_SECONDS = 300
CHECK_SCRIPT = str(Path(__file__).with_name("saml_check.py"))
CHECK_TIMEOUT_SECONDS = 10.0
CHECK_MAX_OUTPUT = 64 * 1024
# The XML checks one API process runs at once (review A2). Measured 2026-11-11: each is a Python
# process of ~0.37 s and ~50 MiB, beside the argon2 slots in an API limited to 384 MiB.
CHECKS_AT_ONCE = 2
CHECK_WAIT_SECONDS = 0.5
MAX_ANSWER_BYTES = 256 * 1024  # the ACS's own limit; nginx's is the first, not the only one
CLOCK_SKEW = timedelta(seconds=300)  # python3-saml's allowed drift
MAX_NEXT = 512
_STATE_LABEL = "argus.saml.state.v1"

_checks = threading.BoundedSemaphore(CHECKS_AT_ONCE)


# A sign-in refused for `code`, from here or from the users rules. "busy" and "off" are not
# refusals of a person and are not audited.
SsoRefusedError = users.SsoRefusedError


@dataclass(frozen=True)
class Idp:
    entity_id: str
    sso_url: str
    certs: tuple[str, ...]


@dataclass(frozen=True)
class SsoConfig:
    public_url: str
    sp_entity_id: str
    acs_url: str
    idp: Idp
    groups_attribute: str
    email_attribute: str
    name_attribute: str
    group_roles: dict[str, Role]


def _check(job: str, request: dict[str, Any]) -> dict[str, Any]:
    """One job in the isolated child. A busy process refuses rather than queueing: a burst of
    answers must not hold every API thread."""
    if not _checks.acquire(timeout=CHECK_WAIT_SECONDS):
        raise SsoRefusedError("busy")
    try:
        result = run_isolated(
            [sys.executable, "-I", "-B", CHECK_SCRIPT],
            stdin=json.dumps({"job": job, **request}).encode(),
            timeout=CHECK_TIMEOUT_SECONDS,
            max_output=CHECK_MAX_OUTPUT,
        )
    except IsolatedRunError:
        raise SsoRefusedError("error") from None
    finally:
        _checks.release()
    answer: dict[str, Any] = json.loads(result.output)
    return answer


@lru_cache(maxsize=1)
def sso_config() -> SsoConfig | None:
    """None when SSO is off. Reads the metadata file once, through the child: an IdP that rolls
    its certificate is picked up when the deployment changes the file and the API restarts.
    Raises ValueError on metadata that holds no entity id, sign-in URL or signing certificate."""
    settings = get_settings()
    if settings.saml_idp_metadata_file is None or settings.public_url is None:
        return None
    base = settings.public_url.rstrip("/")
    metadata = settings.saml_idp_metadata_file.read_text()
    try:
        answer = _check("metadata", {"metadata": metadata})
    except SsoRefusedError:
        answer = {"ok": False}
    if not answer.get("ok"):
        raise ValueError(
            f"{settings.saml_idp_metadata_file}: IdP metadata without an entity id, an "
            "HTTP-Redirect sign-in URL or a signing certificate"
        )
    return SsoConfig(
        public_url=base,
        sp_entity_id=base + METADATA_PATH,
        acs_url=base + ACS_PATH,
        idp=Idp(answer["entity_id"], answer["sso_url"], tuple(answer["certs"])),
        groups_attribute=settings.saml_groups_attribute,
        email_attribute=settings.saml_email_attribute,
        name_attribute=settings.saml_name_attribute,
        group_roles=dict(settings.saml_group_roles),
    )


def _request(config: SsoConfig) -> dict[str, Any]:
    return {
        "sp": {"entity_id": config.sp_entity_id, "acs_url": config.acs_url},
        "idp": {
            "entity_id": config.idp.entity_id,
            "sso_url": config.idp.sso_url,
            "certs": list(config.idp.certs),
        },
    }


def safe_next(path: str | None) -> str:
    """Only a path inside the app: never another site, a protocol-relative URL or a backslash."""
    if (
        not path
        or len(path) > MAX_NEXT
        or not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or any(ord(c) < 0x20 for c in path)
    ):
        return "/"
    return path


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _mac(payload: str) -> str:
    return _b64(hmac.new(derived_key(_STATE_LABEL), payload.encode(), hashlib.sha256).digest())


def _sign_state(request_id: str, next_path: str) -> str:
    payload = _b64(
        json.dumps(
            {"r": request_id, "n": next_path, "e": int(time.time()) + STATE_SECONDS}
        ).encode()
    )
    return f"{payload}.{_mac(payload)}"


def _open_state(cookie: str | None) -> tuple[str, str] | None:
    """(request id, next) from a state cookie this deployment signed and that hasn't expired."""
    if not cookie or cookie.count(".") != 1:
        return None
    payload, mac = cookie.split(".")
    if not hmac.compare_digest(mac, _mac(payload)):
        return None
    try:
        state = json.loads(_unb64(payload))
        expired = int(state["e"]) < time.time()
    except (ValueError, TypeError, KeyError):
        return None
    if expired:
        return None
    return str(state["r"]), safe_next(state.get("n"))


def _authn_request(config: SsoConfig) -> tuple[str, str]:
    """(its id, the IdP URL carrying it) for the HTTP-Redirect binding. Built here, not in the
    child: it reads nothing anyone sent, so an anonymous login start costs no process and can't
    take the answer's check slots. Unsigned, as ADR-0048 decides; the IdP's URL and entity id come
    from the metadata, Argus's from ARGUS_PUBLIC_URL."""
    request_id = "_" + secrets.token_hex(20)
    instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{instant}" '
        f"Destination={quoteattr(config.idp.sso_url)} "
        'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f"AssertionConsumerServiceURL={quoteattr(config.acs_url)}>"
        f"<saml:Issuer>{escape(config.sp_entity_id)}</saml:Issuer>"
        '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" '
        'AllowCreate="true"/></samlp:AuthnRequest>'
    )
    deflate = zlib.compressobj(9, zlib.DEFLATED, -15)  # raw DEFLATE, as the binding requires
    packed = deflate.compress(xml.encode()) + deflate.flush()
    query = urlencode({"SAMLRequest": base64.b64encode(packed).decode()})
    join = "&" if "?" in config.idp.sso_url else "?"
    return request_id, f"{config.idp.sso_url}{join}{query}"


def start(next_path: str | None) -> tuple[str, str]:
    """(the IdP URL to send the browser to, the state cookie's value). Raises SsoRefusedError
    with "off"."""
    config = sso_config()
    if config is None:
        raise SsoRefusedError("off")
    request_id, url = _authn_request(config)
    return url, _sign_state(request_id, safe_next(next_path))


def role_for(groups: list[str], group_roles: dict[str, Role]) -> tuple[Role | None, str | None]:
    """The highest role any of the groups grants, and the group that grants it."""
    best: tuple[Role | None, str | None] = (None, None)
    for group in sorted(g for g in set(groups) if len(g) <= users.MAX_ROLE_GROUP):
        role = group_roles.get(group)
        if role is not None and (best[0] is None or ROLES.index(role) > ROLES.index(best[0])):
            best = (role, group)
    return best


def _remember(conn: Connection, assertion_id: str, not_on_or_after: int | None) -> bool:
    """False when this assertion was already used: a replay."""
    expires = (
        datetime.fromtimestamp(not_on_or_after, UTC)
        if not_on_or_after
        else datetime.now(UTC) + timedelta(seconds=STATE_SECONDS)
    ) + CLOCK_SKEW
    added = conn.execute(
        text("""
        INSERT INTO saml_assertion_seen (assertion_id, expires_at) VALUES (:a, :e)
        ON CONFLICT (assertion_id) DO NOTHING
    """),
        {"a": assertion_id[:256], "e": expires},
    )
    return added.rowcount == 1


def finish(
    conn: Connection,
    *,
    saml_response: str,
    state_cookie: str | None,
    client_ip: str | None,
    user_agent: str | None,
) -> tuple[str, str]:
    """(the session token, where to go next). Raises SsoRefusedError; a refusal the caller must
    audit with refused() and commit, since it may have ended sessions."""
    config = sso_config()
    if config is None:
        raise SsoRefusedError("off")
    state = _open_state(state_cookie)
    if state is None:
        raise SsoRefusedError("state")
    request_id, next_path = state
    answer = _check(
        "acs",
        {
            **_request(config),
            "saml_response": saml_response,
            "request_id": request_id,
            "attributes": {
                "email": config.email_attribute,
                "name": config.name_attribute,
                "groups": config.groups_attribute,
            },
        },
    )
    if not answer.get("ok"):
        raise SsoRefusedError(str(answer.get("code", "invalid")))
    if not answer.get("assertion_id") or not _remember(
        conn, str(answer["assertion_id"]), answer.get("not_on_or_after")
    ):
        raise SsoRefusedError("replay")
    role, group = role_for(list(answer.get("groups", [])), config.group_roles)
    user_id, username = users.sso_user(
        conn,
        external_id=str(answer["name_id"]),
        email=str(answer.get("email", "")),
        display_name=str(answer.get("name", "")),
        role=role,
        role_group=group,
        client_ip=client_ip,
    )
    token = start_session(conn, user_id=user_id, client_ip=client_ip, user_agent=user_agent)
    audit.record(
        conn,
        actor=username,
        action="auth.sso.sign_in",
        detail={"role": role, "group": group},
        client_ip=client_ip,
    )
    return token, next_path


def refused(conn: Connection, *, code: str, client_ip: str | None) -> None:
    """Audits a refusal, once per address and code per window. "busy" and "off" are not
    refusals of a person, so they are not audited."""
    if code in ("busy", "off"):
        return
    audit.record_sso_refused(
        conn,
        actor="sso",
        client_ip=client_ip,
        reason=code,
        window_minutes=get_settings().login_lockout_minutes,
    )


def sp_metadata(config: SsoConfig) -> str:
    """Argus's own metadata for the IdP's set-up: who it is and where to post. No key: Argus
    signs nothing and accepts only signed assertions."""
    return (
        '<?xml version="1.0"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f"entityID={quoteattr(config.sp_entity_id)}>"
        '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
        "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
        '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location={quoteattr(config.acs_url)} index="0" isDefault="true"/>'
        "</md:SPSSODescriptor></md:EntityDescriptor>\n"
    )


__all__ = [
    "ACS_PATH",
    "MAX_ANSWER_BYTES",
    "STATE_COOKIE",
    "STATE_SECONDS",
    "SsoConfig",
    "SsoRefusedError",
    "finish",
    "refused",
    "role_for",
    "safe_next",
    "sp_metadata",
    "sso_config",
    "start",
]
