"""P2.1c.2d.3c — idempotent backend PRIVATE draft executor.

The Browser controls request_id and draft text only. The server computes a semantic
request hash, stages payload under a fresh server UUID, and lets PostgreSQL atomically
choose either the first receipt or the already-committed receipt for the same
(principal_id, request_id).

This is not an HTTP route, production payload store, public publisher or proof of
cross-system crash atomicity.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Callable
from uuid import UUID, uuid4

from private_voice_executor import (
    PrivateVoiceExecutionError, RUNTIME_ROLE, _valid_payload_ref, _validate_intent,
)

CALL_IDEMPOTENT_WRITER = (
    "SELECT * FROM echo_identity.runtime_idempotent_append_private_voice("
    + ",".join(["%s"] * 15)
    + ")"
)


@dataclass(frozen=True)
class IdempotentPrivateVoiceReceipt:
    voice_id: UUID
    revision: int
    visibility: str
    recorded_at: datetime
    replayed: bool


def _request_hash(text: str) -> str:
    # Domain-separated exact UTF-8 text. Unicode normalization is intentionally NOT
    # performed: if the semantic input bytes differ, reusing the key is a conflict.
    return hashlib.sha256(b"echo/private-draft/v1\x00" + text.encode("utf-8", "strict")).hexdigest()


class IdempotentPrivateVoiceExecutor:
    """One idempotent PRIVATE draft operation per principal + request_id.

    store_payload must stage an object dedicated to the supplied server-generated
    voice_id. discard_payload must delete only that staged object; a content-addressed
    shared object cannot safely satisfy this compensation contract without refcounts.
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

    def execute(self, intent: object) -> IdempotentPrivateVoiceReceipt:
        bound, stamp, payload = _validate_intent(intent)
        request_hash = _request_hash(payload.text)
        staged_voice_id = uuid4()
        try:
            payload_ref = _valid_payload_ref(self._store_payload(staged_voice_id, payload.text))
        except PrivateVoiceExecutionError:
            raise
        except Exception:
            raise PrivateVoiceExecutionError("PAYLOAD_STORE_UNAVAILABLE") from None

        try:
            with self._connect_runtime() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT current_user")
                    if cursor.fetchone() != (RUNTIME_ROLE,):
                        raise PrivateVoiceExecutionError("RUNTIME_ROLE_REQUIRED")
                    cursor.execute(
                        CALL_IDEMPOTENT_WRITER,
                        stamp.private_draft_fence_args()
                        + (bound.request_id, request_hash, staged_voice_id, payload_ref),
                    )
                    row = cursor.fetchone()
                    if (row is None or len(row) != 5 or row[1] != 1 or row[2] != "PRIVATE"
                            or not isinstance(row[0], UUID)
                            or not isinstance(row[3], datetime) or row[3].tzinfo is None
                            or type(row[4]) is not bool):
                        raise PrivateVoiceExecutionError("WRITE_CONTRACT_VIOLATION")
                    receipt = IdempotentPrivateVoiceReceipt(row[0], row[1], row[2], row[3], row[4])
            if receipt.replayed:
                # This attempt's staged payload lost to the canonical receipt.
                self._discard_or_raise(payload_ref)
            return receipt
        except PrivateVoiceExecutionError:
            self._discard_or_raise(payload_ref)
            raise
        except Exception as exc:
            self._discard_or_raise(payload_ref)
            if getattr(exc, "sqlstate", None) == "P2001" or getattr(exc, "pgcode", None) == "P2001":
                raise PrivateVoiceExecutionError("IDEMPOTENCY_KEY_REUSED") from None
            raise PrivateVoiceExecutionError("PRIVATE_VOICE_WRITE_REJECTED") from None
