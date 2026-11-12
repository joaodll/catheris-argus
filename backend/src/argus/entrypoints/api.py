"""The API process. Behind the web container's reverse proxy; never published directly."""

import sys

import uvicorn

from argus.api import create_app
from argus.auth import saml
from argus.core.config import get_settings
from argus.core.logging import configure_logging
from argus.core.process import hide_from_children


def main() -> int:
    # First: the SAML check runs in child processes, which must not read this one's environment
    # (the database password and the keyring) through /proc (ADR-0048).
    hide_from_children()
    settings = get_settings()
    configure_logging(settings.log_level)
    # A deployment with SSO checks its IdP metadata now, not at someone's first sign-in.
    saml.sso_config()
    uvicorn.run(
        create_app(),
        host="0.0.0.0",  # noqa: S104 - in a container, behind the proxy; never published
        port=8000,
        log_config=None,
        proxy_headers=True,
        forwarded_allow_ips=settings.trusted_proxies,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
