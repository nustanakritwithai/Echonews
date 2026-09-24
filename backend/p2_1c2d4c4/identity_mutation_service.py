from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from uuid import UUID


class IdentityMutationError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PrincipalMutationResult:
    principal_id: UUID
    enabled: bool
    writer_enabled: bool
    reviewer_enabled: bool
    auth_version: int


@dataclass(frozen=True)
class SessionMutationResult:
    session_key: str
    principal_id: UUID
    auth_version: int
    revoked: bool
    issued_at_ms: int | None = None
    expires_at_ms: int | None = None


class IdentityMutationService:
    """Fixed-command backend adapter. This module is not an HTTP route."""

    def __init__(self, connect_mutation: Callable[[], object]):
        if not callable(connect_mutation):
            raise ValueError('mutation connection callback required')
        self._connect = connect_mutation

    def _one(self, statement: str, params: tuple[object, ...]) -> dict:
        try:
            with self._connect() as connection:
                row = connection.execute(statement, params, prepare=False).fetchone()
        except Exception:
            raise IdentityMutationError('IDENTITY_MUTATION_REJECTED') from None
        if row is None or len(row) != 1 or type(row[0]) is not dict:
            raise IdentityMutationError('IDENTITY_MUTATION_CONTRACT_VIOLATION')
        return row[0]

    @staticmethod
    def _uuid(value: object) -> UUID:
        if type(value) is not UUID or value.int == 0:
            raise IdentityMutationError('INVALID_IDENTITY_MUTATION')
        return value

    @staticmethod
    def _principal(value: dict, expected: UUID) -> PrincipalMutationResult:
        try:
            result = PrincipalMutationResult(
                principal_id=UUID(value['principalId']), enabled=value['enabled'],
                writer_enabled=value['writerEnabled'], reviewer_enabled=value['reviewerEnabled'],
                auth_version=value['authVersion'])
        except Exception:
            raise IdentityMutationError('IDENTITY_MUTATION_CONTRACT_VIOLATION') from None
        if (result.principal_id != expected or type(result.enabled) is not bool
                or type(result.writer_enabled) is not bool or type(result.reviewer_enabled) is not bool
                or type(result.auth_version) is not int or result.auth_version <= 0):
            raise IdentityMutationError('IDENTITY_MUTATION_CONTRACT_VIOLATION')
        return result

    @staticmethod
    def _session(value: dict, expected_key: str, expected_principal: UUID) -> SessionMutationResult:
        try:
            result = SessionMutationResult(
                session_key=value['sessionKey'], principal_id=UUID(value['principalId']),
                auth_version=value['authVersion'], revoked=value['revoked'],
                issued_at_ms=value.get('issuedAtMs'), expires_at_ms=value.get('expiresAtMs'))
        except Exception:
            raise IdentityMutationError('IDENTITY_MUTATION_CONTRACT_VIOLATION') from None
        if (result.session_key != expected_key or result.principal_id != expected_principal
                or type(result.auth_version) is not int or result.auth_version <= 0
                or type(result.revoked) is not bool):
            raise IdentityMutationError('IDENTITY_MUTATION_CONTRACT_VIOLATION')
        return result

    def provision_principal(self, *, principal_id: UUID, issuer: str, subject: str,
                            actor_id: UUID, source_id: UUID) -> PrincipalMutationResult:
        self._uuid(principal_id); self._uuid(actor_id); self._uuid(source_id)
        if (type(issuer) is not str or not issuer.strip() or len(issuer) > 2048
                or type(subject) is not str or not subject.strip() or len(subject) > 255):
            raise IdentityMutationError('INVALID_IDENTITY_MUTATION')
        value = self._one('SELECT echo_identity.runtime_provision_principal(%s,%s,%s,%s,%s)',
                          (principal_id, issuer, subject, actor_id, source_id))
        return self._principal(value, principal_id)

    def change_authority(self, *, principal_id: UUID, expected_auth_version: int,
                         enabled: bool, writer_enabled: bool) -> PrincipalMutationResult:
        self._uuid(principal_id)
        if (type(expected_auth_version) is not int or expected_auth_version <= 0
                or type(enabled) is not bool or type(writer_enabled) is not bool
                or (not enabled and writer_enabled)):
            raise IdentityMutationError('INVALID_IDENTITY_MUTATION')
        value = self._one('SELECT echo_identity.runtime_change_principal_authority(%s,%s,%s,%s)',
                          (principal_id, expected_auth_version, enabled, writer_enabled))
        result = self._principal(value, principal_id)
        if result.reviewer_enabled:
            raise IdentityMutationError('IDENTITY_MUTATION_CONTRACT_VIOLATION')
        return result

    def create_session(self, *, session_key: str, principal_id: UUID, auth_version: int,
                       issued_at_ms: int, expires_at_ms: int) -> SessionMutationResult:
        self._uuid(principal_id)
        if (type(session_key) is not str or len(session_key) != 64
                or any(ch not in '0123456789abcdef' for ch in session_key)
                or type(auth_version) is not int or auth_version <= 0
                or type(issued_at_ms) is not int or type(expires_at_ms) is not int
                or issued_at_ms <= 0 or expires_at_ms <= issued_at_ms):
            raise IdentityMutationError('INVALID_IDENTITY_MUTATION')
        value = self._one('SELECT echo_identity.runtime_create_session(%s,%s,%s,%s,%s)',
                          (session_key, principal_id, auth_version, issued_at_ms, expires_at_ms))
        return self._session(value, session_key, principal_id)

    def revoke_session(self, *, session_key: str, principal_id: UUID) -> SessionMutationResult:
        self._uuid(principal_id)
        if (type(session_key) is not str or len(session_key) != 64
                or any(ch not in '0123456789abcdef' for ch in session_key)):
            raise IdentityMutationError('INVALID_IDENTITY_MUTATION')
        value = self._one('SELECT echo_identity.runtime_revoke_session(%s,%s)',
                          (session_key, principal_id))
        return self._session(value, session_key, principal_id)
