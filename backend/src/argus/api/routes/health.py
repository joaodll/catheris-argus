from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text

from argus.api.deps import Db

router = APIRouter(tags=["health"])


class Health(BaseModel):
    status: str


@router.get("/health")
def health() -> Health:
    """Liveness: the process answers. No database call."""
    return Health(status="ok")


@router.get("/ready")
def ready(conn: Db) -> Health:
    """Readiness: the database answers."""
    conn.execute(text("SELECT 1"))
    return Health(status="ready")
