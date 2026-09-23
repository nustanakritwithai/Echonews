"""P2.1c.2d.4b — backend PRIVATE owner-read adapter.

This is intentionally NOT an HTTP route. The untrusted caller may provide only a
signed bearer token plus a JSON object containing ``voice_id``. Durable identity,
Actor/Source, principal/session data and the DB authorization tuple come from the
existing signed-token Boundary + PostgreSQL registry. The database returns only an
opaque payload locator to this trusted backend adapter; the locator is resolved by a
trusted callback and is never returned to the caller.

The adapter deliberately reuses the current P2.1c.2d.4a rule that PRIVATE owner
reads require the existing ``voice:draft:create`` capability. Introducing a distinct
read-only entitlement is a later registry/schema decision, not something inferred
here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from typing import Callable
from uuid import UUID

from identity_boundary import AuthorizationStamp, Boundary, BoundaryError

READ_RUNTIME_ROLE = "echo_private_owner_read_runtime"
CALL_OWNER_READ = (
    "SELECT * FROM echo_identity.runtime_read_private_owner_voice("
    + ",".join(["%s"] * 12)
    + ")"
)
_MAX_REQUEST_BYTES = 1024
_MAX_PAYLOAD_BYTES = 8192
_MAX_TEXT_CHARS = 2000


class PrivateOwnerReadError(Exception):
    """Public-safe category only; never interpolate secrets, token or payload data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PrivateOwnerVoice:
    voice_id: UUID
    revision: int
    text: str
    recorded_at: datetime


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _parse_request(raw_body: bytes) -> UUID:
    try:
        if type(raw_body) is not bytes or not 0 < len(raw_body) <= _MAX_REQUEST_BYTES:
            raise ValueError("invalid request bytes")
        body = json.loads(raw_body.decode("utf-8", "strict"), object_pairs_hook=_pairs)
        if type(body) is not dict or set(body) != {"voice_id"}:
            raise ValueError("voice_id is the only accepted field")
        value = body["voice_id"]
        if type(value) is not str:
            raise ValueError("voice_id must be text")
        voice_id = UUID(value)
        if str(voice_id) != value or voice_id.int == 0:
            raise ValueError("canonical nonnil UUID required")
        return voice_id
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise PrivateOwnerReadError("INVALID_READ_REQUEST") from None


def _owner_read_stamp(boundary: object, authorization: str | None) -> AuthorizationStamp:
    """Reuse the proven signed-token authentication core without accepting body auth.

    Boundary._authenticate is an in-process backend method, not request data. Keeping
    this dependency explicit avoids duplicating JWT verification. A future Boundary
    API may expose a public read-auth method; until then tests pin this integration.
    """
    if type(boundary) is not Boundary:
        raise PrivateOwnerReadError("TRUSTED_BOUNDARY_REQUIRED")
    try:
        binding, claims, _effective_exp = boundary._authenticate(authorization)
    except BoundaryError as exc:
        raise PrivateOwnerReadError(exc.code) from None
    except Exception:
        raise PrivateOwnerReadError("IDENTITY_BACKEND_UNAVAILABLE") from None

    if "voice:draft:create" not in binding.capabilities:
        raise PrivateOwnerReadError("CAPABILITY_REQUIRED")
    if binding.principal_id is None or binding.source_id is None or binding.session_key is None:
        raise PrivateOwnerReadError("IDENTITY_REJECTED")

    try:
        return AuthorizationStamp(
            issuer=binding.issuer,
            subject=binding.subject,
            session_key=binding.session_key,
            principal_id=binding.principal_id,
            actor_id=binding.actor_id,
            source_id=binding.source_id,
            auth_version=binding.revision,
            capability="voice:draft:create",
            token_issued_ms=claims["iat"] * 1000,
            token_not_before_ms=claims["nbf"] * 1000,
            token_expires_ms=claims["exp"] * 1000,
            key_set_version=boundary._config.key_set_version,
        )
    except Exception:
        raise PrivateOwnerReadError("IDENTITY_REJECTED") from None


def _decode_payload(value: object) -> str:
    if type(value) is not bytes or not 0 < len(value) <= _MAX_PAYLOAD_BYTES:
        raise PrivateOwnerReadError("PAYLOAD_CONTRACT_VIOLATION")
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeError:
        raise PrivateOwnerReadError("PAYLOAD_CONTRACT_VIOLATION") from None
    if not text.strip() or len(text) > _MAX_TEXT_CHARS or "\x00" in text:
        raise PrivateOwnerReadError("PAYLOAD_CONTRACT_VIOLATION")
    return text


class PrivateOwnerReadAdapter:
    """Resolve one current PRIVATE owner Voice without leaking its payload locator."""

    def __init__(self, boundary: Boundary, connect_runtime: Callable[[], object],
                 resolve_payload: Callable[[str], bytes]):
        if type(boundary) is not Boundary or not callable(connect_runtime) or not callable(resolve_payload):
            raise ValueError("trusted boundary, runtime connection and payload resolver required")
        self._boundary = boundary
        self._connect_runtime = connect_runtime
        self._resolve_payload = resolve_payload

    def read(self, authorization: str | None, raw_body: bytes) -> PrivateOwnerVoice | None:
        voice_id = _parse_request(raw_body)
        stamp = _owner_read_stamp(self._boundary, authorization)

        try:
            with self._connect_runtime() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT current_user")
                    if cursor.fetchone() != (READ_RUNTIME_ROLE,):
                        raise PrivateOwnerReadError("RUNTIME_ROLE_REQUIRED")
                    cursor.execute(CALL_OWNER_READ, stamp.private_draft_fence_args() + (voice_id,))
                    row = cursor.fetchone()
        except PrivateOwnerReadError:
            raise
        except Exception:
            raise PrivateOwnerReadError("PRIVATE_OWNER_READ_REJECTED") from None

        # Unknown/other-owner/non-current/non-PRIVATE objects intentionally collapse
        # to the same result so a valid account cannot use this as a private oracle.
        if row is None:
            return None
        if (len(row) != 6 or row[0] != voice_id or row[1] != 1
                or type(row[2]) is not str or not row[2]
                or row[3] != "PRIVATE" or not isinstance(row[4], datetime)
                or row[4].tzinfo is None or row[5] != "COMMITTED"):
            raise PrivateOwnerReadError("READ_CONTRACT_VIOLATION")

        payload_ref = row[2]
        try:
            payload_bytes = self._resolve_payload(payload_ref)
        except PrivateOwnerReadError:
            raise
        except Exception:
            raise PrivateOwnerReadError("PAYLOAD_UNAVAILABLE") from None
        text = _decode_payload(payload_bytes)
        return PrivateOwnerVoice(voice_id=row[0], revision=row[1], text=text,
                                 recorded_at=row[4])
