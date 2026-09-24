from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


POLICY = "MONOTONIC_SIGNED_BEARER_ROTATION_V1"


class Decision(str, Enum):
    REPLAY_CURRENT = "REPLAY_CURRENT"
    ROTATED = "ROTATED"
    REJECT_NO_ACTIVE_USE_REPEAT_LOGIN = "REJECT_NO_ACTIVE_USE_REPEAT_LOGIN"
    REJECT_STALE_OR_EQUAL_BEARER = "REJECT_STALE_OR_EQUAL_BEARER"
    REJECT_REVOKED_PREDECESSOR = "REJECT_REVOKED_PREDECESSOR"
    REJECT_IDENTITY = "REJECT_IDENTITY"
    REJECT_AUTHORITY = "REJECT_AUTHORITY"
    REJECT_TOKEN_TIME = "REJECT_TOKEN_TIME"
    CONTRACT_VIOLATION = "CONTRACT_VIOLATION"


@dataclass(frozen=True)
class Principal:
    subject: str
    auth_version: int
    enabled: bool = True
    activated: bool = True


@dataclass(frozen=True)
class Session:
    session_key: str
    subject: str
    auth_version: int
    issued_at_ms: int
    expires_at_ms: int
    revoked: bool = False
    replaced_by: str | None = None

    def live(self, now_ms: int, current_auth_version: int) -> bool:
        return (
            not self.revoked
            and self.auth_version == current_auth_version
            and now_ms < self.expires_at_ms
        )


@dataclass(frozen=True)
class Candidate:
    session_key: str
    subject: str
    auth_version: int
    issued_at_ms: int
    not_before_ms: int
    expires_at_ms: int


@dataclass(frozen=True)
class Result:
    decision: Decision
    sessions: tuple[Session, ...]
    current_session_key: str | None


def _current_live(sessions: tuple[Session, ...], now_ms: int, auth_version: int) -> list[Session]:
    return [s for s in sessions if s.live(now_ms, auth_version)]


def rotate_active_session(
    principal: Principal,
    sessions: tuple[Session, ...],
    candidate: Candidate,
    now_ms: int,
) -> Result:
    """Pure policy model; production code must reproduce these externally visible semantics."""
    if not principal.enabled or not principal.activated or candidate.subject != principal.subject:
        return Result(Decision.REJECT_IDENTITY, sessions, None)
    if candidate.auth_version != principal.auth_version:
        return Result(Decision.REJECT_AUTHORITY, sessions, None)
    if not (candidate.issued_at_ms <= now_ms and candidate.not_before_ms <= now_ms < candidate.expires_at_ms):
        return Result(Decision.REJECT_TOKEN_TIME, sessions, None)

    live = _current_live(sessions, now_ms, principal.auth_version)
    if len(live) > 1:
        return Result(Decision.CONTRACT_VIOLATION, sessions, None)
    if not live:
        return Result(Decision.REJECT_NO_ACTIVE_USE_REPEAT_LOGIN, sessions, None)

    current = live[0]

    # Exact current bearer retry is idempotent.
    if candidate.session_key == current.session_key:
        if candidate.issued_at_ms != current.issued_at_ms:
            return Result(Decision.CONTRACT_VIOLATION, sessions, None)
        return Result(Decision.REPLAY_CURRENT, sessions, current.session_key)

    # A previously known revoked key can never be resurrected as a successor.
    for session in sessions:
        if session.session_key == candidate.session_key:
            if session.revoked:
                return Result(Decision.REJECT_REVOKED_PREDECESSOR, sessions, current.session_key)
            return Result(Decision.CONTRACT_VIOLATION, sessions, current.session_key)

    # New proof must be strictly fresher than the currently authorized bearer.
    if candidate.issued_at_ms <= current.issued_at_ms:
        return Result(Decision.REJECT_STALE_OR_EQUAL_BEARER, sessions, current.session_key)

    rotated: list[Session] = []
    for session in sessions:
        if session.session_key == current.session_key:
            rotated.append(replace(session, revoked=True, replaced_by=candidate.session_key))
        else:
            rotated.append(session)
    successor = Session(
        session_key=candidate.session_key,
        subject=candidate.subject,
        auth_version=candidate.auth_version,
        issued_at_ms=candidate.issued_at_ms,
        expires_at_ms=candidate.expires_at_ms,
    )
    rotated.append(successor)
    out = tuple(rotated)
    live_after = _current_live(out, now_ms, principal.auth_version)
    if len(live_after) != 1 or live_after[0].session_key != candidate.session_key:
        return Result(Decision.CONTRACT_VIOLATION, sessions, current.session_key)
    return Result(Decision.ROTATED, out, candidate.session_key)
