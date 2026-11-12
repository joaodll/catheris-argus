"""Development only: readies the `sso` profile's Keycloak for Argus (ADR-0048).

The realm import (realm.json) holds no password. This sets each test user's password from
ARGUS_E2E_SSO_PASSWORD, which is also Keycloak's admin password, then writes the IdP's metadata
into the `saml` volume, where the API reads ARGUS_SAML_IDP_METADATA_FILE.

Run by `docker compose --profile sso run --rm sso-setup`, on the host network: Keycloak's address
is http://127.0.0.1:8180, the one the browser uses, so the metadata names it.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

KEYCLOAK = "http://127.0.0.1:8180"
REALM = "argus"
USERS = ("alice", "bob", "carol", "dave")
OUT = Path("/saml/metadata.xml")


def _call(method: str, path: str, *, token: str = "", body: object = None, form: dict[str, str] | None = None) -> bytes:
    data = None
    headers = {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(KEYCLOAK + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - a fixed local URL
        return bytes(response.read())


def main() -> int:
    password = os.environ.get("ARGUS_E2E_SSO_PASSWORD", "")
    if len(password) < 12:
        print("Set ARGUS_E2E_SSO_PASSWORD (12 characters or more) for the dev IdP.", file=sys.stderr)
        return 2
    deadline = time.monotonic() + 180
    while True:
        try:
            _call("GET", f"/realms/{REALM}")
            break
        except (urllib.error.URLError, OSError):
            if time.monotonic() > deadline:
                print("Keycloak did not answer in 3 minutes.", file=sys.stderr)
                return 1
            time.sleep(2)
    token = json.loads(
        _call(
            "POST",
            "/realms/master/protocol/openid-connect/token",
            form={"grant_type": "password", "client_id": "admin-cli", "username": "admin",
                  "password": password},
        )
    )["access_token"]
    for name in USERS:
        [user] = json.loads(_call("GET", f"/admin/realms/{REALM}/users?username={name}&exact=true", token=token))
        _call(
            "PUT",
            f"/admin/realms/{REALM}/users/{user['id']}/reset-password",
            token=token,
            body={"type": "password", "value": password, "temporary": False},
        )
    OUT.write_bytes(_call("GET", f"/realms/{REALM}/protocol/saml/descriptor"))
    OUT.chmod(0o644)
    print(f"Users {', '.join(USERS)} ready; IdP metadata written to the saml volume.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
