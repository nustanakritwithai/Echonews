"""P2.1c.2d.3d — durable payload lifecycle + recovery for PRIVATE drafts.

This module does not pretend PostgreSQL and an external payload store share one
transaction. Instead it uses a durable database attempt ledger and an idempotent
payload-store contract:

reserve in DB -> durable stage in store -> Voice/receipt + NEEDS_COMMIT in one DB txn
-> idempotent store commit -> DB COMMITTED acknowledgement.

A recovery worker can finish NEEDS_COMMIT attempts and discard abandoned/stale
stages after process crashes. Returned receipts are never considered ready until the
canonical payload is COMMITTED. No HTTP route, PUBLIC publication, read path or
production payload-store implementation is provided here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Callable
from uuid import UUID, uuid4

from private_voice_executor import (
    PrivateVoiceExecutionError, RUNTIME_ROLE, _valid_payload_ref, _validate_intent,
)
from idempotent_private_voice_executor import (
    IdempotentPrivateVoiceReceipt, _request_hash,
)

CALL_RESERVE = (
    "SELECT * FROM echo_identity.runtime_reserve_private_payload_attempt("
    + ",".join(["%s"] * 14) + ")"
)
CALL_WRITE = (
    "SELECT * FROM echo_identity.runtime_recoverable_idempotent_append_private_voice("
    + ",".join(["%s"] * 15) + ")"
)
CALL_GET = "SELECT * FROM echo_identity.runtime_get_private_payload_attempt(%s)"
CALL_LIST = "SELECT * FROM echo_identity.runtime_list_private_payload_recovery(%s)"
CALL_COMMITTED = "SELECT echo_identity.runtime_mark_private_payload_committed(%s,%s)"
CALL_ABANDON = "SELECT echo_identity.runtime_abandon_private_payload_attempt(%s,%s)"
CALL_CLAIM_STALE = "SELECT echo_identity.runtime_claim_stale_private_payload_attempt(%s)"
CALL_DISCARDED = "SELECT echo_identity.runtime_mark_private_payload_discarded(%s)"


class DurablePayloadStore(Protocol):
    """Trusted store contract.

    stage() MUST durably persist bytes before returning. The returned ref is stable
    across STAGED -> COMMITTED and unique to the supplied attempt/voice UUID.
    commit() and discard() MUST be idempotent. find_staged() must recover a stage
    from attempt_id after process restart, or return None when no stage exists.
    """

    def stage(self, attempt_id: UUID, text: str) -> str: ...
    def commit(self, payload_ref: str) -> None: ...
    def discard(self, payload_ref: str) -> None: ...
    def find_staged(self, attempt_id: UUID) -> str | None: ...


@dataclass(frozen=True)
class PayloadAttemptSnapshot:
    attempt_id: UUID
    state: str
    payload_ref: str | None
    created_at: datetime
    recover_after: datetime
    canonical_voice_id: UUID | None
    canonical_revision: int | None
    canonical_visibility: str | None
    canonical_recorded_at: datetime | None
    canonical_attempt_id: UUID | None
    canonical_payload_ref: str | None
    canonical_payload_state: str | None

    def receipt(self, replayed: bool) -> IdempotentPrivateVoiceReceipt | None:
        if (self.canonical_voice_id is None or self.canonical_revision != 1
                or self.canonical_visibility != "PRIVATE"
                or not isinstance(self.canonical_recorded_at, datetime)
                or self.canonical_recorded_at.tzinfo is None
                or self.canonical_payload_state != "COMMITTED"):
            return None
        return IdempotentPrivateVoiceReceipt(
            self.canonical_voice_id, 1, "PRIVATE", self.canonical_recorded_at, replayed
        )


class PayloadRecoveryCoordinator:
    """Recover only durable attempt-ledger states; never infer authorization."""

    def __init__(self, connect_runtime: Callable[[], object], store: DurablePayloadStore):
        if not callable(connect_runtime):
            raise ValueError("trusted runtime connection required")
        for name in ("stage", "commit", "discard", "find_staged"):
            if not callable(getattr(store, name, None)):
                raise ValueError("durable payload store contract required")
        self._connect_runtime = connect_runtime
        self._store = store

    def _call(self, sql: str, params: tuple, *, one: bool = True):
        try:
            with self._connect_runtime() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT current_user")
                    if cursor.fetchone() != (RUNTIME_ROLE,):
                        raise PrivateVoiceExecutionError("RUNTIME_ROLE_REQUIRED")
                    cursor.execute(sql, params)
                    return cursor.fetchone() if one else cursor.fetchall()
        except PrivateVoiceExecutionError:
            raise
        except Exception as exc:
            state = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
            if state == "P2001":
                raise PrivateVoiceExecutionError("IDEMPOTENCY_KEY_REUSED") from None
            if state == "P2002":
                raise PrivateVoiceExecutionError("PAYLOAD_ATTEMPT_REJECTED") from None
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_DB_UNAVAILABLE") from None

    def snapshot(self, attempt_id: UUID) -> PayloadAttemptSnapshot | None:
        row = self._call(CALL_GET, (attempt_id,))
        if row is None:
            return None
        if len(row) != 12 or not isinstance(row[0], UUID) or row[1] not in {
            "RESERVED", "NEEDS_COMMIT", "COMMITTED", "ABANDONED", "DISCARDED"
        }:
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
        if not isinstance(row[3], datetime) or row[3].tzinfo is None:
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
        if not isinstance(row[4], datetime) or row[4].tzinfo is None:
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
        return PayloadAttemptSnapshot(*row)

    def _commit_canonical(self, snap: PayloadAttemptSnapshot) -> PayloadAttemptSnapshot:
        if snap.state != "NEEDS_COMMIT" or snap.payload_ref is None:
            return snap
        ref = _valid_payload_ref(snap.payload_ref)
        try:
            self._store.commit(ref)
        except Exception:
            raise PrivateVoiceExecutionError("PAYLOAD_FINALIZATION_PENDING") from None
        self._call(CALL_COMMITTED, (snap.attempt_id, ref))
        updated = self.snapshot(snap.attempt_id)
        if updated is None or updated.state != "COMMITTED":
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
        return updated

    def _discard_abandoned(self, snap: PayloadAttemptSnapshot) -> PayloadAttemptSnapshot:
        if snap.state != "ABANDONED":
            return snap
        ref = snap.payload_ref
        if ref is None:
            try:
                ref = self._store.find_staged(snap.attempt_id)
            except Exception:
                raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_REQUIRED") from None
        if ref is not None:
            ref = _valid_payload_ref(ref)
            try:
                self._store.discard(ref)
            except Exception:
                raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_REQUIRED") from None
        self._call(CALL_DISCARDED, (snap.attempt_id,))
        updated = self.snapshot(snap.attempt_id)
        if updated is None or updated.state != "DISCARDED":
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
        return updated

    def recover_attempt(self, attempt_id: UUID, *, claim_reserved: bool = False,
                        abandon_reserved_ref: str | None = None) -> PayloadAttemptSnapshot:
        snap = self.snapshot(attempt_id)
        if snap is None:
            raise PrivateVoiceExecutionError("PAYLOAD_ATTEMPT_NOT_FOUND")

        # If this attempt lost an idempotent race, heal the canonical stage first.
        if (snap.canonical_attempt_id is not None
                and snap.canonical_attempt_id != snap.attempt_id
                and snap.canonical_payload_state == "NEEDS_COMMIT"):
            self.recover_attempt(snap.canonical_attempt_id)
            snap = self.snapshot(attempt_id) or snap

        if snap.state == "RESERVED" and abandon_reserved_ref is not None:
            self._call(CALL_ABANDON, (attempt_id, _valid_payload_ref(abandon_reserved_ref)))
            snap = self.snapshot(attempt_id) or snap
        elif snap.state == "RESERVED" and claim_reserved:
            claimed = self._call(CALL_CLAIM_STALE, (attempt_id,))
            if claimed == (True,):
                snap = self.snapshot(attempt_id) or snap
        if snap.state == "NEEDS_COMMIT":
            snap = self._commit_canonical(snap)
        elif snap.state == "ABANDONED":
            snap = self._discard_abandoned(snap)
        return snap

    def sweep(self, limit: int = 100) -> tuple[int, int]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("recovery limit must be 1..1000")
        rows = self._call(CALL_LIST, (limit,), one=False)
        recovered = 0
        pending = 0
        for row in rows:
            if len(row) != 4 or not isinstance(row[0], UUID):
                raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
            attempt_id, state, _, _ = row
            snap = self.recover_attempt(attempt_id, claim_reserved=(state == "RESERVED"))
            if snap.state in ("COMMITTED", "DISCARDED"):
                recovered += 1
            else:
                pending += 1
        return recovered, pending


class RecoverablePrivateVoiceExecutor:
    """PRIVATE draft executor that never returns before canonical payload commit."""

    def __init__(self, connect_runtime: Callable[[], object], store: DurablePayloadStore):
        self._recovery = PayloadRecoveryCoordinator(connect_runtime, store)
        self._connect_runtime = connect_runtime
        self._store = store

    def _call(self, sql: str, params: tuple):
        return self._recovery._call(sql, params)

    def _finish_from_snapshot(self, attempt_id: UUID, *, replayed: bool) -> IdempotentPrivateVoiceReceipt:
        snap = self._recovery.recover_attempt(attempt_id)
        # Snapshot for a losing attempt points to canonical receipt/payload.
        if snap.canonical_attempt_id is not None and snap.canonical_attempt_id != snap.attempt_id:
            canonical = self._recovery.recover_attempt(snap.canonical_attempt_id)
            snap = self._recovery.snapshot(attempt_id) or snap
            if canonical.state != "COMMITTED":
                raise PrivateVoiceExecutionError("PAYLOAD_FINALIZATION_PENDING")
        receipt = snap.receipt(replayed)
        if receipt is None:
            raise PrivateVoiceExecutionError("PAYLOAD_FINALIZATION_PENDING")
        return receipt

    def execute(self, intent: object) -> IdempotentPrivateVoiceReceipt:
        bound, stamp, payload = _validate_intent(intent)
        request_hash = _request_hash(payload.text)
        attempt_id = uuid4()  # Candidate voice_id if this attempt becomes canonical.

        try:
            row = self._call(
                CALL_RESERVE,
                stamp.private_draft_fence_args() + (bound.request_id, request_hash, attempt_id),
            )
            if (row is None or len(row) != 3 or row[0] != attempt_id
                    or not isinstance(row[1], datetime) or row[1].tzinfo is None
                    or not isinstance(row[2], datetime) or row[2].tzinfo is None):
                raise PrivateVoiceExecutionError("PAYLOAD_RESERVATION_CONTRACT_VIOLATION")
        except PrivateVoiceExecutionError:
            raise
        except Exception:
            raise PrivateVoiceExecutionError("PAYLOAD_RESERVATION_REJECTED") from None

        try:
            payload_ref = _valid_payload_ref(self._store.stage(attempt_id, payload.text))
        except PrivateVoiceExecutionError:
            raise
        except Exception:
            # Durable reservation remains. Recovery will eventually terminalize it.
            raise PrivateVoiceExecutionError("PAYLOAD_STORE_UNAVAILABLE") from None

        try:
            row = self._call(
                CALL_WRITE,
                stamp.private_draft_fence_args()
                + (bound.request_id, request_hash, attempt_id, payload_ref),
            )
            if (row is None or len(row) != 8 or not isinstance(row[0], UUID)
                    or row[1] != 1 or row[2] != "PRIVATE"
                    or not isinstance(row[3], datetime) or row[3].tzinfo is None
                    or type(row[4]) is not bool or not isinstance(row[5], UUID)
                    or not isinstance(row[6], str)
                    or row[7] not in ("NEEDS_COMMIT", "COMMITTED")):
                raise PrivateVoiceExecutionError("WRITE_CONTRACT_VIOLATION")
        except PrivateVoiceExecutionError as exc:
            # If the DB call has returned a definite conflict/rejection, resolve the
            # durable attempt before touching the staged object. A committed outcome
            # will no longer be RESERVED and therefore cannot be abandoned here.
            try:
                self._recovery.recover_attempt(attempt_id, abandon_reserved_ref=payload_ref)
            except PrivateVoiceExecutionError:
                pass
            raise exc
        except Exception as exc:
            try:
                snap = self._recovery.recover_attempt(attempt_id, claim_reserved=True)
                receipt = snap.receipt(False)
                if receipt is not None:
                    return receipt
            except PrivateVoiceExecutionError:
                pass
            if getattr(exc, "sqlstate", None) == "P2001" or getattr(exc, "pgcode", None) == "P2001":
                raise PrivateVoiceExecutionError("IDEMPOTENCY_KEY_REUSED") from None
            raise PrivateVoiceExecutionError("PRIVATE_VOICE_WRITE_REJECTED") from None

        written_voice_id, _, _, recorded_at, replayed, canonical_attempt_id, canonical_ref, _ = row
        # Finalize canonical payload first. This is idempotent and recoverable.
        canonical = self._recovery.recover_attempt(canonical_attempt_id)
        if canonical.state != "COMMITTED" or canonical.payload_ref != canonical_ref:
            raise PrivateVoiceExecutionError("PAYLOAD_FINALIZATION_PENDING")

        # A replay attempt's own staged payload is now provably non-canonical.
        if replayed and canonical_attempt_id != attempt_id:
            losing = self._recovery.recover_attempt(attempt_id)
            if losing.state != "DISCARDED":
                raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_REQUIRED")

        snap = self._recovery.snapshot(attempt_id)
        if snap is None:
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
        receipt = snap.receipt(replayed)
        if receipt is None or receipt.voice_id != written_voice_id or receipt.recorded_at != recorded_at:
            raise PrivateVoiceExecutionError("PAYLOAD_RECOVERY_CONTRACT_VIOLATION")
        return receipt
