"""P2.1c.2c.3 durable registry adapter for the existing signed-token Boundary.

The adapter consumes ONLY issuer/subject/jti after signature validation. It derives
an issuer-bound non-bearer session lookup key and resolves one PostgreSQL snapshot.
It does not verify tokens, create sessions, grant roles, write news, or cache auth.
"""
from __future__ import annotations

import hashlib
from typing import Callable
from uuid import UUID

from identity_boundary import ActorBinding

_DOMAIN = b"echo-session-key-v1\x00"


def derive_session_key(issuer: str, jti: str) -> str:
    if (type(issuer) is not str or type(jti) is not str or not issuer or not jti
            or "\x00" in issuer or "\x00" in jti
            or len(issuer) > 2048 or len(jti) > 256):
        raise ValueError("invalid verified session identity")
    raw = _DOMAIN + issuer.encode("utf-8", "strict") + b"\x00" + jti.encode("utf-8", "strict")
    return hashlib.sha256(raw).hexdigest()


def _uuid(value: object) -> UUID:
    if type(value) is not str:
        raise ValueError("registry UUID must be text")
    parsed = UUID(value)
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("registry UUID must be canonical and nonnil")
    return parsed


def _integer(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("registry integer required")
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("registry boolean required")
    return value


class PostgresRegistryAdapter:
    """Resolve a verified token identity against the current durable registry.

    connect() must return a fresh psycopg-compatible connection to the authoritative
    database. This reference deliberately performs no local authorization cache.
    """

    def __init__(self, connect: Callable[[], object]):
        if not callable(connect):
            raise ValueError("fresh database connection factory required")
        self._connect = connect

    def resolve_binding(self, issuer: str, subject: str, jti: str) -> ActorBinding | None:
        key = derive_session_key(issuer, jti)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT echo_identity.lookup_session(%s,%s,%s),
                              floor(extract(epoch FROM clock_timestamp())*1000)::bigint""",
                    (issuer, subject, key),
                )
                row = cursor.fetchone()
        if row is None or row[0] is None:
            return None
        snapshot, now_ms = row
        if type(snapshot) is not dict or set(snapshot) != {"principal", "session"}:
            raise ValueError("unexpected registry snapshot")
        principal, session = snapshot["principal"], snapshot["session"]
        if type(principal) is not dict or type(session) is not dict:
            raise ValueError("unexpected registry sections")
        expected_principal = {"principalId", "issuer", "subject", "actorId", "sourceId",
                              "actorKind", "enabled", "authVersion", "writerEnabled",
                              "reviewerEnabled"}
        expected_session = {"sessionKey", "principalId", "authVersion", "issuedAtMs",
                            "expiresAtMs", "revoked"}
        if set(principal) != expected_principal or set(session) != expected_session:
            raise ValueError("unexpected registry fields")

        principal_id = _uuid(principal["principalId"])
        actor_id = _uuid(principal["actorId"])
        source_id = _uuid(principal["sourceId"])
        if (principal["issuer"] != issuer or principal["subject"] != subject
                or principal["actorKind"] != "HUMAN"
                or not _boolean(principal["enabled"])):
            return None
        principal_version = _integer(principal["authVersion"])
        if principal_version < 1:
            raise ValueError("invalid authority version")
        writer = _boolean(principal["writerEnabled"])
        reviewer = _boolean(principal["reviewerEnabled"])

        if (_uuid(session["principalId"]) != principal_id or session["sessionKey"] != key
                or _boolean(session["revoked"])):
            return None
        session_version = _integer(session["authVersion"])
        issued_ms = _integer(session["issuedAtMs"])
        expires_ms = _integer(session["expiresAtMs"])
        now_ms = _integer(now_ms)
        if (session_version != principal_version or expires_ms <= issued_ms
                or now_ms < issued_ms or now_ms >= expires_ms):
            return None

        capabilities = set()
        if writer:
            capabilities.add("voice:draft:create")
        if reviewer:
            capabilities.add("assessment:review")
        return ActorBinding(
            issuer=issuer,
            subject=subject,
            actor_id=actor_id,
            actor_kind="HUMAN",
            capabilities=frozenset(capabilities),
            revision=principal_version,
            enabled=True,
            tokens_valid_from=(issued_ms + 999) // 1000,
            source_id=source_id,
            authorization_expires_at=expires_ms // 1000,
            principal_id=principal_id,
            session_key=key,
        )
