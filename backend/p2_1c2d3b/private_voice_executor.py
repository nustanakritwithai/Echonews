"""P2.1c.2d.3b — backend-only PRIVATE Voice execution adapter.

This module accepts only a server-created BoundIntent from the signed-token boundary,
asks a trusted payload store for an opaque reference, and invokes the sealed
PostgreSQL PRIVATE writer under the least-privilege runtime role.

It is NOT an HTTP route, LOGIN/session issuer, public publisher, payload-store
implementation, idempotency layer, or protection against arbitrary malicious code
already executing inside the backend process.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable
from uuid import UUID, uuid4

from identity_boundary import AuthorizationStamp, BoundIntent, DraftIntent

RUNTIME_ROLE = "echo_private_draft_runtime"
CALL_PRIVATE_WRITER = (
    "SELECT * FROM echo_identity.runtime_append_private_voice("
    + ",".join(["%s"] * 13)
    + ")"
)


class PrivateVoiceExecutionError(Exception):
    """Public-safe category; never include token, subject, payload or DB details."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PrivateVoiceReceipt:
    voice_id: UUID
    revision: int
    visibility: str
    recorded_at: datetime


def _valid_payload_ref(value: object) -> str:
    if type(value) is not str or not value.strip() or len(value) > 4096:
        raise PrivateVoiceExecutionError("PAYLOAD_STORE_CONTRACT_VIOLATION")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError:
        raise PrivateVoiceExecutionError("PAYLOAD_STORE_CONTRACT_VIOLATION") from None
    if "\x00" in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise PrivateVoiceExecutionError("PAYLOAD_STORE_CONTRACT_VIOLATION")
    return value


def _validate_intent(intent: object) -> tuple[BoundIntent, AuthorizationStamp, DraftIntent]:
    # Exact server types deliberately reject request dicts / JSON-shaped lookalikes.
    if type(intent) is not BoundIntent:
        raise PrivateVoiceExecutionError("INVALID_SERVER_INTENT")
    if intent.command != "CREATE_VOICE_DRAFT" or type(intent.payload) is not DraftIntent:
        raise PrivateVoiceExecutionError("UNSUPPORTED_SERVER_INTENT")
    stamp = intent.authorization_stamp
    if type(stamp) is not AuthorizationStamp:
        raise PrivateVoiceExecutionError("AUTHORIZATION_STAMP_REQUIRED")
    if stamp.capability != "voice:draft:create":
        raise PrivateVoiceExecutionError("CAPABILITY_MISMATCH")
    if (intent.actor_id != stamp.actor_id
            or intent.source_id != stamp.source_id
            or intent.binding_revision != stamp.auth_version
            or intent.key_set_version != stamp.key_set_version
            or intent.policy_version != stamp.policy_version
            or intent.issued_at * 1000 != stamp.token_issued_ms
            or intent.expires_at * 1000 > stamp.token_expires_ms):
        raise PrivateVoiceExecutionError("AUTHORIZATION_STAMP_MISMATCH")
    text = intent.payload.text
    if type(text) is not str or not text.strip() or len(text) > 2000 or "\x00" in text:
        raise PrivateVoiceExecutionError("INVALID_SERVER_INTENT")
    return intent, stamp, intent.payload


class PrivateVoiceExecutor:
    """Narrow backend executor for one immutable PRIVATE revision-1 Voice.

    connect_runtime() MUST return a fresh connection whose current_user is exactly
    echo_private_draft_runtime. The factory is trusted backend configuration, never
    request-controlled. store_payload() / discard_payload() are also trusted server
    callbacks; the request can provide only DraftIntent.text through Boundary.bind.
    """

    def __init__(self, connect_runtime: Callable[[], object],
                 store_payload: Callable[[UUID, str], str],
                 discard_payload: Callable[[str], None]):
        if not all(callable(x) for x in (connect_runtime, store_payload, discard_payload)):
            raise ValueError("trusted runtime connection and payload callbacks required")
        self._connect_runtime = connect_runtime
        self._store_payload = store_payload
        self._discard_payload = discard_payload

    def _discard_or_raise(self, ref: str) -> None:
        try:
            self._discard_payload(ref)
        except Exception:
            raise PrivateVoiceExecutionError("PAYLOAD_COMPENSATION_FAILED") from None

    def execute(self, intent: object) -> PrivateVoiceReceipt:
        _, stamp, payload = _validate_intent(intent)
        voice_id = uuid4()  # Backend-owned; request_id is never reused as voice_id.

        try:
            payload_ref = _valid_payload_ref(self._store_payload(voice_id, payload.text))
        except PrivateVoiceExecutionError:
            raise
        except Exception:
            raise PrivateVoiceExecutionError("PAYLOAD_STORE_UNAVAILABLE") from None

        try:
            with self._connect_runtime() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT current_user")
                    role_row = cursor.fetchone()
                    if role_row != (RUNTIME_ROLE,):
                        raise PrivateVoiceExecutionError("RUNTIME_ROLE_REQUIRED")
                    cursor.execute(CALL_PRIVATE_WRITER,
                                   stamp.private_draft_fence_args() + (voice_id, payload_ref))
                    row = cursor.fetchone()
                    if (row is None or len(row) != 4 or row[0] != voice_id
                            or row[1] != 1 or row[2] != "PRIVATE"
                            or not isinstance(row[3], datetime)
                            or row[3].tzinfo is None):
                        raise PrivateVoiceExecutionError("WRITE_CONTRACT_VIOLATION")
                    receipt = PrivateVoiceReceipt(row[0], row[1], row[2], row[3])
            return receipt
        except PrivateVoiceExecutionError:
            self._discard_or_raise(payload_ref)
            raise
        except Exception:
            self._discard_or_raise(payload_ref)
            raise PrivateVoiceExecutionError("PRIVATE_VOICE_WRITE_REJECTED") from None
