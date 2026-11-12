"""The only code that reads an identity provider's XML (ADR-0048, section 2).

It runs as its own process through core.process.run_isolated, with an environment built from
nothing, so a flaw in libxml2 or xmlsec reached by a hostile answer can't read the API's keyring or
use its database login. It is run by path with `python -I`, so it imports nothing from Argus: only
python3-saml and the standard library.

One JSON request on stdin, one JSON result in $HOME/out. Two jobs:
- "metadata": read the IdP's metadata file's text; return its entity id, its sign-in URL and every
  signing certificate (several, so the IdP can roll its certificate).
- "acs": check one answer against everything below; return what Argus needs, or a refusal code.

Refusal codes are fixed words. The library's own message is never returned, because it can quote
the answer it refused.
"""

import json
import os
import resource
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
from onelogin.saml2.errors import OneLogin_Saml2_ValidationError as V
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser as Parser
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings

# A hostile answer must not be able to take the API pod's memory: the address space is capped
# before any XML is read (ADR-0048 review A2). Measured 2026-11-11: a real check peaks at 54 MiB
# of address space (VmPeak), so 192 MiB leaves room, and two at once stay below the pod's 384 MiB.
ADDRESS_SPACE_BYTES = 192 * 1024 * 1024

PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NAMEID_FORMATS = (PERSISTENT, EMAIL)
REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


def _settings(request: dict[str, Any]) -> dict[str, Any]:
    sp, idp = request["sp"], request["idp"]
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp["entity_id"],
            "assertionConsumerService": {"url": sp["acs_url"], "binding": POST},
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        },
        "idp": {
            "entityId": idp["entity_id"],
            "singleSignOnService": {"url": idp["sso_url"], "binding": REDIRECT},
            "x509certMulti": {"signing": idp["certs"]},
        },
        "security": {
            "authnRequestsSigned": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantAssertionsEncrypted": False,
            "wantNameId": True,
            "wantAttributeStatement": False,
            "rejectDeprecatedAlgorithm": True,
            "requestedAuthnContext": False,
            "allowRepeatAttributeName": False,
        },
    }


def _metadata(request: dict[str, Any]) -> dict[str, Any]:

    try:
        parsed = Parser.parse(request["metadata"], required_sso_binding=REDIRECT).get("idp", {})
    except Exception:  # not metadata at all: a DOCTYPE, broken XML, another document
        return {"ok": False, "code": "metadata"}
    multi = parsed.get("x509certMulti", {}).get("signing") or []
    certs = [c for c in [*multi, parsed.get("x509cert")] if c]
    sso = parsed.get("singleSignOnService", {}).get("url")
    if not parsed.get("entityId") or not sso or not certs:
        return {"ok": False, "code": "metadata"}
    return {
        "ok": True,
        "entity_id": parsed["entityId"],
        "sso_url": sso,
        "certs": sorted(set(certs)),
    }


def _code(error_code: int | None) -> str:

    if error_code in (
        V.ASSERTION_EXPIRED,
        V.ASSERTION_TOO_EARLY,
        V.RESPONSE_EXPIRED,
        V.SESSION_EXPIRED,
    ):
        return "expired"
    if error_code == V.STATUS_CODE_IS_NOT_SUCCESS:
        return "idp-refused"
    return "invalid"


def _acs(request: dict[str, Any]) -> dict[str, Any]:

    settings = OneLogin_Saml2_Settings(_settings(request), sp_validation_only=True)
    acs = urlsplit(request["sp"]["acs_url"])
    https = acs.scheme == "https"
    # The URL the answer must have been sent to comes from ARGUS_PUBLIC_URL, never from headers.
    where = {
        "https": "on" if https else "off",
        "http_host": acs.hostname,
        "server_port": str(acs.port or (443 if https else 80)),
        "script_name": acs.path,
    }
    try:
        response = OneLogin_Saml2_Response(settings, request["saml_response"])
        # InResponseTo is required, not only compared when present (the library's behaviour).
        if response.get_in_response_to() != request["request_id"]:
            return {"ok": False, "code": "unsolicited"}
        if not response.is_valid(where, request_id=request["request_id"], raise_exceptions=True):
            return {"ok": False, "code": "invalid"}
    except OneLogin_Saml2_ValidationError as exc:
        return {"ok": False, "code": _code(exc.code), "error_code": exc.code}
    except Exception:  # malformed input of any kind: a DOCTYPE, bad base64, broken XML
        return {"ok": False, "code": "invalid"}

    if response.get_nameid_format() not in NAMEID_FORMATS:
        return {"ok": False, "code": "nameid"}
    attributes = response.get_attributes()  # from the signed assertion only

    def values(name: str) -> list[str]:
        return [str(v) for v in attributes.get(name, []) if v is not None]

    names = request["attributes"]
    email = values(names["email"])[:1] if names["email"] else [response.get_nameid()]
    display = values(names["name"])[:1] if names["name"] else []
    not_after = response.get_assertion_not_on_or_after()
    return {
        "ok": True,
        "name_id": response.get_nameid(),
        "email": email[0] if email else "",
        "name": display[0] if display else "",
        "groups": values(names["groups"]),
        "assertion_id": response.get_assertion_id(),
        "not_on_or_after": int(not_after) if not_after else None,
    }


def main() -> int:
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES))
    request = json.loads(sys.stdin.buffer.read())
    job = {"metadata": _metadata, "acs": _acs}[request["job"]]
    result = job(request)
    Path(os.environ["HOME"], "out").write_text(json.dumps(result))
    print("ok" if result.get("ok") else result.get("code", "refused"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
