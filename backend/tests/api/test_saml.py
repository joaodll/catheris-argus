"""SAML sign-in (ADR-0048) end to end through the API, with a throwaway IdP made in the test.

Every answer goes through the real child process (saml_check.py, run_isolated)."""

import base64
import json
import threading
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from lxml import etree
from pydantic import ValidationError
from sqlalchemy import Engine, text
from tests.api import saml_idp
from tests.api.conftest import PASSWORD, add_user, csrf

from argus.auth import saml
from argus.core.config import Settings, get_settings

pytestmark = pytest.mark.db

ROLES = {"sec-team": "operator", "admins": "admin", "readers": "viewer"}
SRC = Path(__file__).resolve().parents[2] / "src" / "argus"


@pytest.fixture(scope="module")
def idp() -> tuple[str, str]:
    return saml_idp.keypair()


@pytest.fixture
def sso(
    client: TestClient, idp: tuple[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[TestClient]:
    meta = tmp_path / "idp.xml"
    meta.write_text(saml_idp.metadata(idp[1]))
    monkeypatch.setenv("ARGUS_PUBLIC_URL", saml_idp.PUBLIC_URL)
    monkeypatch.setenv("ARGUS_SAML_IDP_METADATA_FILE", str(meta))
    monkeypatch.setenv("ARGUS_SAML_GROUPS_ATTRIBUTE", "groups")
    monkeypatch.setenv("ARGUS_SAML_EMAIL_ATTRIBUTE", "email")
    monkeypatch.setenv("ARGUS_SAML_GROUP_ROLES", json.dumps(ROLES))
    get_settings.cache_clear()
    saml.sso_config.cache_clear()
    yield client
    get_settings.cache_clear()
    saml.sso_config.cache_clear()


def _login(http: TestClient, next_path: str = "/investigate/findings") -> str:
    started = http.get(
        "/api/v1/auth/saml/login", params={"next": next_path}, follow_redirects=False
    )
    assert started.status_code == 302, started.text
    assert started.headers["location"].startswith(saml_idp.IDP_SSO + "?SAMLRequest=")
    cookie = started.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=none" in cookie
    assert "Path=/api/v1/auth/saml/acs" in cookie
    return saml_idp.request_id(started.headers["location"])


def _post(http: TestClient, answer: str) -> Any:
    return http.post("/api/v1/auth/saml/acs", data={"SAMLResponse": answer}, follow_redirects=False)


def _refused_with(response: Any, code: str) -> None:
    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/sign-in?reason=sso-{code}"), response.headers
    assert "argus_session" not in response.headers.get("set-cookie", "")


def _users(owner: Engine) -> list[Any]:
    with owner.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT username, role, role_group, auth_source, is_active "
                    "FROM app_user WHERE auth_source = 'saml'"
                )
            )
        )


def _audit(owner: Engine, action: str) -> list[Any]:
    with owner.connect() as conn:
        return list(
            conn.execute(
                text("SELECT actor, detail FROM audit_log WHERE action = :a ORDER BY id"),
                {"a": action},
            )
        )


def test_a_signed_answer_signs_in_with_the_highest_role_of_the_groups(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    rid = _login(sso)
    answer = saml_idp.Answer(rid, groups=["sec-team", "admins", "other"])
    done = _post(sso, answer.signed(*idp))
    assert done.status_code == 303 and done.headers["location"] == "/investigate/findings"
    session = sso.get("/api/v1/auth/session").json()
    assert session["username"] == "alice@example.test"
    assert (session["role"], session["auth_source"]) == ("admin", "saml")
    [user] = _users(owner)
    assert (user.role, user.role_group) == ("admin", "admins")
    assert [a.detail["source"] for a in _audit(owner, "user.created")] == ["saml"]
    assert len(_audit(owner, "auth.sso.sign_in")) == 1


def _tampered(signed: str) -> str:
    xml = base64.b64decode(signed).replace(b"nameid-alice", b"nameid-mallo")
    return base64.b64encode(xml).decode()


def _doctype(signed: str) -> str:
    xml = base64.b64decode(signed)
    entity = b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    return base64.b64encode(entity + xml).decode()


CASES: list[tuple[str, dict[str, Any], str, str]] = [
    # (id, Answer fields, how it is sent, expected code)
    ("unsigned", {}, "unsigned", "invalid"),
    ("another-key", {}, "other-key", "invalid"),
    ("tampered", {}, "tampered", "invalid"),
    ("doctype", {}, "doctype", "invalid"),
    ("wrong-audience", {"audience": "https://other.test"}, "signed", "invalid"),
    ("wrong-destination", {"destination": "https://other.test/acs"}, "signed", "invalid"),
    ("wrong-recipient", {"recipient": "https://other.test/acs"}, "signed", "invalid"),
    ("wrong-issuer", {"issuer": "https://evil.test"}, "signed", "invalid"),
    ("two-assertions", {"assertions": 2}, "signed", "invalid"),
    ("expired", {"issued_minutes_ago": 20}, "signed", "expired"),
    ("transient-nameid", {"name_id_format": saml_idp.TRANSIENT}, "signed", "nameid"),
    ("idp-initiated", {"in_response_to": None}, "signed", "unsolicited"),
    ("other-request", {"in_response_to": "_another"}, "signed", "unsolicited"),
]


@pytest.mark.parametrize(
    ("fields", "how", "code"), [c[1:] for c in CASES], ids=[c[0] for c in CASES]
)
def test_a_bad_answer_is_refused_with_its_code_and_audited(
    sso: TestClient,
    owner: Engine,
    idp: tuple[str, str],
    fields: dict[str, Any],
    how: str,
    code: str,
) -> None:
    rid = _login(sso)
    answer = saml_idp.Answer(**{"in_response_to": rid, **fields})
    sent = {
        "unsigned": answer.unsigned,
        "signed": lambda: answer.signed(*idp),
        "other-key": lambda: answer.signed(*saml_idp.keypair("other")),
        "tampered": lambda: _tampered(answer.signed(*idp)),
        "doctype": lambda: _doctype(answer.signed(*idp)),
    }[how]()
    _refused_with(_post(sso, sent), code)
    assert _users(owner) == []
    assert [a.detail["reason"] for a in _audit(owner, "auth.sso.refused")] == [code]


def test_without_the_browsers_state_cookie_the_answer_is_refused(
    sso: TestClient, idp: tuple[str, str]
) -> None:
    rid = _login(sso)
    sso.cookies.delete(saml.STATE_COOKIE, path=saml.ACS_PATH)
    _refused_with(_post(sso, saml_idp.Answer(rid).signed(*idp)), "state")


def test_a_forged_state_cookie_is_refused(sso: TestClient, idp: tuple[str, str]) -> None:
    rid = _login(sso)
    forged = base64.urlsafe_b64encode(json.dumps({"r": rid, "n": "/", "e": 2**40}).encode())
    sso.cookies.set(saml.STATE_COOKIE, f"{forged.decode().rstrip('=')}.AAAA", path=saml.ACS_PATH)
    _refused_with(_post(sso, saml_idp.Answer(rid).signed(*idp)), "state")


def test_an_answer_used_twice_is_a_replay(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    rid = _login(sso)
    state = sso.cookies.get(saml.STATE_COOKIE)
    answer = saml_idp.Answer(rid).signed(*idp)
    assert _post(sso, answer).status_code == 303
    sso.cookies.set(saml.STATE_COOKIE, state or "", path=saml.ACS_PATH)  # a copied cookie too
    _refused_with(_post(sso, answer), "replay")


def test_no_matching_group_is_refused_and_ends_the_users_sessions(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    rid = _login(sso)
    assert _post(sso, saml_idp.Answer(rid, assertion_id="_a1").signed(*idp)).status_code == 303
    assert sso.get("/api/v1/auth/session").status_code == 200

    rid = _login(sso)
    refused = _post(sso, saml_idp.Answer(rid, groups=["other"], assertion_id="_a2").signed(*idp))
    _refused_with(refused, "no-group")
    assert sso.get("/api/v1/auth/session").status_code == 401  # the earlier session ended


def test_a_group_change_changes_the_role_at_the_next_sign_in(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    for number, groups in enumerate((["readers"], ["sec-team"])):
        rid = _login(sso)
        answer = saml_idp.Answer(rid, groups=groups, assertion_id=f"_g{number}")
        assert _post(sso, answer.signed(*idp)).status_code == 303
    [user] = _users(owner)
    assert (user.role, user.role_group) == ("operator", "sec-team")
    [changed] = _audit(owner, "user.role_from_groups")
    assert changed.detail == {"before": "viewer", "after": "operator", "group": "sec-team"}


def test_a_new_email_for_the_same_nameid_follows_and_is_audited(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    for number, email in enumerate(("alice@example.test", "alice.b@example.test")):
        rid = _login(sso)
        answer = saml_idp.Answer(rid, email=email, assertion_id=f"_e{number}")
        assert _post(sso, answer.signed(*idp)).status_code == 303
    assert [u.username for u in _users(owner)] == ["alice.b@example.test"]
    assert len(_audit(owner, "user.email_from_idp")) == 1


def test_an_sso_sign_in_never_takes_over_a_local_user(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    with owner.begin() as conn:
        conn.execute(
            text("UPDATE app_user SET email = 'alice@example.test' WHERE username = 'admin'")
        )
    rid = _login(sso)
    _refused_with(_post(sso, saml_idp.Answer(rid).signed(*idp)), "conflict")
    assert _users(owner) == []


def test_a_deactivated_sso_user_stays_out(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    rid = _login(sso)
    assert _post(sso, saml_idp.Answer(rid, assertion_id="_d1").signed(*idp)).status_code == 303
    with owner.begin() as conn:
        conn.execute(text("UPDATE app_user SET is_active = false WHERE auth_source = 'saml'"))
    rid = _login(sso)
    _refused_with(_post(sso, saml_idp.Answer(rid, assertion_id="_d2").signed(*idp)), "inactive")


def test_a_rolled_idp_certificate_is_accepted_beside_the_old_one(
    sso: TestClient, idp: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = saml_idp.keypair("rolled")
    meta = tmp_path / "rolled.xml"
    meta.write_text(saml_idp.metadata(idp[1], new[1]))
    monkeypatch.setenv("ARGUS_SAML_IDP_METADATA_FILE", str(meta))
    get_settings.cache_clear()
    saml.sso_config.cache_clear()
    rid = _login(sso)
    assert _post(sso, saml_idp.Answer(rid).signed(*new)).status_code == 303


def test_an_answer_over_the_size_limit_is_refused(sso: TestClient) -> None:
    _login(sso)
    _refused_with(_post(sso, "A" * (saml.MAX_ANSWER_BYTES + 1)), "invalid")


def test_a_busy_process_says_so_without_an_audit_row(
    sso: TestClient, owner: Engine, idp: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    rid = _login(sso)  # reads the metadata once, as the API does at start
    monkeypatch.setattr(saml, "_checks", threading.BoundedSemaphore(1))
    saml._checks.acquire()  # every slot held
    assert _login(sso)  # starting costs no slot: it reads nothing anyone sent
    _refused_with(_post(sso, saml_idp.Answer(rid).signed(*idp)), "busy")
    assert _audit(owner, "auth.sso.refused") == []


def test_a_check_that_fails_or_runs_out_of_time_is_an_error_not_a_sign_in(
    sso: TestClient, owner: Engine, idp: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise saml.IsolatedRunError("stopped after 10 s")

    rid = _login(sso)
    monkeypatch.setattr(saml, "run_isolated", broken)
    _refused_with(_post(sso, saml_idp.Answer(rid).signed(*idp)), "error")
    assert _users(owner) == []


def test_an_expired_state_cookie_is_refused(sso: TestClient, idp: tuple[str, str]) -> None:
    rid = _login(sso)
    payload = base64.urlsafe_b64encode(json.dumps({"r": rid, "n": "/", "e": 1}).encode())
    payload_text = payload.decode().rstrip("=")
    sso.cookies.set(
        saml.STATE_COOKIE, f"{payload_text}.{saml._mac(payload_text)}", path=saml.ACS_PATH
    )
    _refused_with(_post(sso, saml_idp.Answer(rid).signed(*idp)), "state")


def test_a_new_email_another_sso_user_holds_is_refused(
    sso: TestClient, owner: Engine, idp: tuple[str, str]
) -> None:
    for number, (name_id, email) in enumerate(
        (("nameid-alice", "alice@example.test"), ("nameid-bob", "bob@example.test"))
    ):
        rid = _login(sso)
        answer = saml_idp.Answer(rid, name_id=name_id, email=email, assertion_id=f"_n{number}")
        assert _post(sso, answer.signed(*idp)).status_code == 303
    rid = _login(sso)
    taken = saml_idp.Answer(rid, name_id="nameid-bob", email="alice@example.test")
    _refused_with(_post(sso, taken.signed(*idp)), "conflict")


def test_the_authn_request_names_argus_and_the_idp(sso: TestClient) -> None:
    started = sso.get("/api/v1/auth/saml/login", follow_redirects=False)
    encoded = parse_qs(urlsplit(started.headers["location"]).query)["SAMLRequest"][0]
    request = etree.fromstring(zlib.decompress(base64.b64decode(encoded), -15))
    assert request.get("Destination") == saml_idp.IDP_SSO
    assert request.get("AssertionConsumerServiceURL") == saml_idp.ACS
    issuer = request.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    assert issuer is not None and issuer.text == saml_idp.SP_ENTITY


def test_metadata_that_is_not_metadata_stops_the_start(
    sso: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad.xml"
    bad.write_text("<html>not metadata</html>")
    monkeypatch.setenv("ARGUS_SAML_IDP_METADATA_FILE", str(bad))
    get_settings.cache_clear()
    saml.sso_config.cache_clear()
    with pytest.raises(ValueError, match="IdP metadata without"):
        saml.sso_config()


def test_with_local_sign_in_off_password_changes_are_refused(
    signed_in: TestClient, sso: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_LOCAL_SIGN_IN", "false")
    get_settings.cache_clear()
    changed = signed_in.put(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "another long passphrase"},
        headers=csrf(signed_in),
    )
    assert changed.status_code == 403


@pytest.mark.parametrize(
    "path",
    ["//evil.test/x", "https://evil.test", "/\\evil.test", "", None, "/x\n/y"],
    ids=["protocol-relative", "absolute", "backslash", "empty", "none", "newline"],
)
def test_next_stays_inside_the_app(path: str | None) -> None:
    assert saml.safe_next(path) == "/"


def test_sso_users_get_no_role_password_or_unlock_from_an_admin(
    sso: TestClient, owner: Engine, idp: tuple[str, str], signed_in: TestClient
) -> None:
    other = TestClient(sso.app, base_url="https://testserver")
    rid = _login(other)
    assert _post(other, saml_idp.Answer(rid).signed(*idp)).status_code == 303
    with owner.connect() as conn:
        uid = conn.execute(text("SELECT id FROM app_user WHERE auth_source = 'saml'")).scalar_one()
    h = csrf(signed_in)
    assert (
        signed_in.patch(f"/api/v1/users/{uid}", json={"role": "viewer"}, headers=h).status_code
        == 409
    )
    assert (
        signed_in.post(
            f"/api/v1/users/{uid}/password", json={"password": "a long new passphrase"}, headers=h
        ).status_code
        == 409
    )
    assert signed_in.post(f"/api/v1/users/{uid}/unlock", headers=h).status_code == 409
    own = other.put(
        "/api/v1/auth/password",
        json={"current_password": "x", "new_password": "a long new passphrase"},
        headers=csrf(other),
    )
    assert own.status_code == 403
    assert (
        signed_in.patch(f"/api/v1/users/{uid}", json={"is_active": False}, headers=h).status_code
        == 200
    )
    users = signed_in.get("/api/v1/users").json()["items"]
    sso_user = next(u for u in users if u["id"] == uid)
    assert (sso_user["auth_source"], sso_user["role_group"]) == ("saml", "sec-team")


def test_the_last_local_admin_is_kept_even_beside_sso_admins(
    sso: TestClient, owner: Engine, idp: tuple[str, str], signed_in: TestClient
) -> None:
    other = TestClient(sso.app, base_url="https://testserver")
    rid = _login(other)
    assert _post(other, saml_idp.Answer(rid, groups=["admins"]).signed(*idp)).status_code == 303
    add_user(owner, "second", role="viewer")
    h = csrf(other)
    with owner.connect() as conn:
        admin_id = conn.execute(
            text("SELECT id FROM app_user WHERE username = 'admin'")
        ).scalar_one()
    refused = other.patch(f"/api/v1/users/{admin_id}", json={"is_active": False}, headers=h)
    assert refused.status_code == 409 and "password" in refused.json()["detail"]


def test_with_local_sign_in_off_passwords_are_refused(
    sso: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_LOCAL_SIGN_IN", "false")
    get_settings.cache_clear()
    assert sso.get("/api/v1/auth/methods").json() == {"local": False, "sso": True}
    refused = sso.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert refused.status_code == 403


def test_methods_metadata_and_the_admins_read_only_card(
    sso: TestClient, signed_in: TestClient
) -> None:
    assert sso.get("/api/v1/auth/methods").json() == {"local": True, "sso": True}
    meta = sso.get("/api/v1/auth/saml/metadata")
    assert meta.status_code == 200 and saml_idp.ACS in meta.text
    assert 'WantAssertionsSigned="true"' in meta.text
    card = signed_in.get("/api/v1/settings/sign-in").json()
    assert (card["sso"], card["acs_url"], card["idp_entity_id"]) == (
        True,
        saml_idp.ACS,
        saml_idp.IDP_ENTITY,
    )
    assert {g["group"]: g["role"] for g in card["group_roles"]} == ROLES


def test_without_sso_the_saml_routes_say_so(client: TestClient) -> None:
    saml.sso_config.cache_clear()
    assert client.get("/api/v1/auth/methods").json() == {"local": True, "sso": False}
    _refused_with(client.get("/api/v1/auth/saml/login", follow_redirects=False), "off")
    assert client.get("/api/v1/auth/saml/metadata").status_code == 404


@pytest.mark.parametrize(
    "env",
    [
        {"saml_idp_metadata_file": "/x.xml"},  # no public URL
        {
            "saml_idp_metadata_file": "/x.xml",
            "public_url": "https://a.test",
            "saml_group_roles": {"g": "admin"},
        },  # no groups attribute
        {
            "saml_idp_metadata_file": "/x.xml",
            "public_url": "https://a.test",
            "saml_groups_attribute": "groups",
        },  # no map
        {
            "saml_idp_metadata_file": "/x.xml",
            "public_url": "https://a.test",
            "saml_groups_attribute": "groups",
            "saml_group_roles": {"g": "owner"},
        },  # unknown role
        {"public_url": "http://argus.example.test"},  # plain http off loopback
        {"public_url": "https://a.test/argus"},  # a path
        {"local_sign_in": False},  # nobody could sign in
        {
            "saml_idp_metadata_file": "/x.xml",
            "public_url": "https://a.test",
            "saml_groups_attribute": "groups",
            "saml_group_roles": {"g": "admin"},
        },  # no keyring
    ],
    ids=[
        "no-url",
        "no-attribute",
        "no-map",
        "unknown-role",
        "http",
        "path",
        "no-way-in",
        "no-keyring",
    ],
)
def test_a_half_configured_sign_in_refuses_to_start(env: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Settings(db_password="x", **env)  # type: ignore[arg-type]


def test_http_is_allowed_on_localhost_for_development() -> None:
    Settings(db_password="x", public_url="http://localhost:8080")  # type: ignore[arg-type]


def test_only_the_isolated_check_imports_the_saml_library() -> None:
    importers = sorted(
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if "onelogin" in p.read_text() and p.name != "saml_check.py"
    )
    assert importers == []


@pytest.mark.parametrize(
    ("fields", "code"),
    [
        ({"email": "not an address"}, "email"),
        ({"name_id": "n" * 513}, "nameid"),
        ({"groups": ["g" * 257]}, "no-group"),
    ],
    ids=["bad-email", "long-nameid", "long-group"],
)
def test_odd_values_from_the_idp_are_refused_not_errors(
    sso: TestClient, owner: Engine, idp: tuple[str, str], fields: dict[str, Any], code: str
) -> None:
    rid = _login(sso)
    _refused_with(_post(sso, saml_idp.Answer(rid, **fields).signed(*idp)), code)
    assert _users(owner) == []
