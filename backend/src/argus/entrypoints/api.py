"""The API process. Behind the web container's reverse proxy; never published directly."""

import sys

import uvicorn

from argus.api import create_app
from argus.core.config import get_settings
from argus.core.logging import configure_logging


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
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
