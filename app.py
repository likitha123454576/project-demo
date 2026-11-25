"""Training demo API for production packaging and API security concepts.

This intentionally small example uses runtime-injected demo credentials. Replace
this authentication layer with your organization's OIDC/JWT identity provider in
production; do not use these demo tokens as a production identity system.
"""

import hmac
import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

APP_ENV = os.getenv("APP_ENV", "local")
RELEASE_VERSION = os.getenv("RELEASE_VERSION", "local")

app = FastAPI(
    title="Production Packaging Training API - Version 2",
    version=RELEASE_VERSION,
    docs_url=None if APP_ENV == "production" else "/docs",
    redoc_url=None if APP_ENV == "production" else "/redoc",
)



class Caller(BaseModel):
    """Authority derived by the server from a validated demo credential."""

    subject: str
    tenant: str
    scopes: frozenset[str]


class ActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=40, pattern=r"^[a-z_]+$")
    record_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")


# Demo-only fixed records. A real service would load these from an authorized store.
RECORDS = {
    "tenant-a": {"record-101": {"status": "ready", "owner": "tenant-a"}},
    "tenant-b": {"record-202": {"status": "ready", "owner": "tenant-b"}},
}


def authenticate(authorization: Annotated[str | None, Header()] = None) -> Caller:
    """Authenticate a demo bearer token and derive its authority server-side."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    supplied = authorization.removeprefix("Bearer ")
    reader_token = os.getenv("DEMO_READER_TOKEN", "")
    admin_token = os.getenv("DEMO_ADMIN_TOKEN", "")

    if reader_token and hmac.compare_digest(supplied, reader_token):
        return Caller(subject="demo-reader", tenant="tenant-a", scopes=frozenset({"records:read"}))
    if admin_token and hmac.compare_digest(supplied, admin_token):
        return Caller(
            subject="demo-admin",
            tenant="tenant-a",
            scopes=frozenset({"records:read", "actions:run"}),
        )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


def require_scope(scope: str):
    def check_scope(caller: Annotated[Caller, Depends(authenticate)]) -> Caller:
        if scope not in caller.scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permission")
        return caller

    return check_scope


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    """Liveness endpoint; keep it free of sensitive dependency details."""
    return {"status": "ok"}


@app.get("/version")
def version() -> dict[str, str]:
    return {"release": RELEASE_VERSION, "environment": APP_ENV}


@app.get("/v1/tenants/{tenant_id}/records/{record_id}")
def get_record(
    tenant_id: str,
    record_id: str,
    caller: Annotated[Caller, Depends(require_scope("records:read"))],
) -> dict[str, str]:
    """Read only a record owned by the authenticated caller's tenant."""
    if tenant_id != caller.tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Resource access denied")
    record = RECORDS.get(caller.tenant, {}).get(record_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")
    return {"id": record_id, **record}


@app.post("/v1/actions", status_code=status.HTTP_202_ACCEPTED)
def run_action(
    request: ActionRequest,
    caller: Annotated[Caller, Depends(require_scope("actions:run"))],
) -> dict[str, str]:
    """Demo action endpoint; authorization is checked before any tool would run."""
    if request.action != "refresh_record":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported action")
    if request.record_id not in RECORDS.get(caller.tenant, {}):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Resource access denied")
    # A real tool call goes here, using caller-scoped authority, never a master key.
    return {"accepted": "true", "action": request.action, "record_id": request.record_id}
