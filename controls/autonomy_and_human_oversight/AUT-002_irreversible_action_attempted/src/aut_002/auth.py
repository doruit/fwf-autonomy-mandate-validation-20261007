"""App Service authenticated identity adapter for the ACS approval resolver."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Mapping
from uuid import UUID

SESSION_SECONDS = 300


@dataclass(frozen=True)
class Operator:
    reference: str
    roles: frozenset[str]
    authenticated_at: float

    def can_approve(self) -> bool:
        return "OpsManager" in self.roles and 0 <= time.time() - self.authenticated_at < SESSION_SECONDS


def operator_from_headers(headers: Mapping[str, str], *, tenant: str, secret: str) -> Operator | None:
    if not tenant or len(secret) < 32:
        return None
    try:
        lowered = {key.lower(): value for key, value in headers.items()}
        principal = json.loads(base64.b64decode(lowered["x-ms-client-principal"], validate=True))
        if principal["auth_typ"] != "aad":
            return None
        claims: dict[str, list[str]] = {}
        for claim in principal["claims"]:
            claims.setdefault(claim["typ"], []).append(claim["val"])
        tenant_claims = claims.get("http://schemas.microsoft.com/identity/claims/tenantid", claims.get("tid", []))
        subjects = claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier", claims.get("oid", []))
        if tenant_claims != [tenant] or len(subjects) != 1:
            return None
        UUID(subjects[0])
        roles = frozenset(claims.get(principal["role_typ"], []))
        if not roles.intersection({"DemoUser", "OpsManager"}):
            return None
        if any(value != "user" for value in claims.get("idtyp", ["user"])):
            return None
        reference = hmac.new(secret.encode(), f"{tenant}:{subjects[0]}".encode(), hashlib.sha256).hexdigest()
        return Operator(reference, roles, time.time())
    except (KeyError, TypeError, ValueError, AttributeError):
        return None