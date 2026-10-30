"""The HTTP API (/api/v1): thin routers over module interfaces. Described by OpenAPI, which
the frontend's client is generated from (the only contract between backend and frontend)."""

from argus.api.app import create_app

__all__ = ["create_app"]
