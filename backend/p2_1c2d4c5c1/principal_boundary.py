"""c5c.1: signed bearer + untrusted proof reference -> disabled Principal.

Server-internal boundary, not HTTP. Reuses c5b signature/profile verification.
A proof UUID is a reference only; never accepts a chosen Principal/Actor/Source.
"""
from dataclasses import dataclass
from typing import Callable
from uuid import UUID

import psycopg
from identity_boundary import Config, _json_object
from account_link_boundary import _strict_signed_identity, _ms, SignedAccountLinkError

PROVISION_SQL = 'SELECT echo_identity.runtime_provision_signed_principal(%s,%s,%s,%s,%s,%s)'
CLOCK_SQL = 'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint'
MAX_MS = 9007199254740991


class PrincipalProvisionError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PrincipalReceipt:
    principal_id: UUID

    @property
    def ready_for_execution(self) -> bool:
        return False


def canonical_uuid(value) -> UUID:
    if type(value) is not str:
        raise ValueError('UUID text required')
    parsed = UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError('canonical nonnil UUID required')
    return parsed


class SignedPrincipalBoundary:
    def __init__(self, config: Config, connect_runtime: Callable):
        if type(config) is not Config or not callable(connect_runtime):
            raise ValueError('trusted config and transaction-owning pool required')
        self._config = config
        self._connect_runtime = connect_runtime

    def provision(self, authorization: str | None, raw_body: bytes) -> PrincipalReceipt:
        try:
            body = _json_object(raw_body, 512)
            if set(body) != {'proof_id'}:
                raise ValueError('only a proof reference is accepted')
            proof_id = canonical_uuid(body['proof_id'])
        except (ValueError, TypeError, KeyError, RecursionError):
            raise PrincipalProvisionError('INVALID_PRINCIPAL_REQUEST') from None
        try:
            claims = _strict_signed_identity(self._config, authorization)
        except SignedAccountLinkError:
            raise PrincipalProvisionError('IDENTITY_REJECTED') from None
        # Intersection of token and registry contracts; never trim/case-fold.
        if len(claims['sub']) > 255:
            raise PrincipalProvisionError('IDENTITY_REJECTED')
        issued, not_before, expires = (_ms(claims[k]) for k in ('iat','nbf','exp'))
        params = (proof_id, self._config.issuer, claims['sub'], issued, not_before, expires)
        try:
            with self._connect_runtime() as c:
                row = c.execute(PROVISION_SQL, params).fetchone()
                if row is None or len(row) != 1 or type(row[0]) is not dict:
                    raise PrincipalProvisionError('PRINCIPAL_CONTRACT_VIOLATION')
                value = row[0]
                if set(value) != {'principalId','proofId','issuer','subject','proofExpiresAtMs'}:
                    raise PrincipalProvisionError('PRINCIPAL_CONTRACT_VIOLATION')
                try:
                    principal_id = canonical_uuid(value['principalId'])
                    returned_proof = canonical_uuid(value['proofId'])
                except (ValueError, TypeError, AttributeError):
                    raise PrincipalProvisionError('PRINCIPAL_CONTRACT_VIOLATION') from None
                proof_expiry = value['proofExpiresAtMs']
                if (returned_proof != proof_id or value['issuer'] != self._config.issuer
                        or value['subject'] != claims['sub'] or type(proof_expiry) is not int
                        or not 0 < proof_expiry <= MAX_MS):
                    raise PrincipalProvisionError('PRINCIPAL_CONTRACT_VIOLATION')
                row = c.execute(CLOCK_SQL).fetchone()
                if row is None or len(row) != 1 or type(row[0]) is not int or not 0 <= row[0] <= MAX_MS:
                    raise PrincipalProvisionError('PRINCIPAL_CONTRACT_VIOLATION')
                now = row[0]
                if now < issued or now < not_before or now >= min(expires, proof_expiry):
                    raise PrincipalProvisionError('PRINCIPAL_PROVISION_REJECTED')
                receipt = PrincipalReceipt(principal_id)
        except PrincipalProvisionError:
            raise
        except psycopg.Error as error:
            if error.sqlstate in ('22023','23514','23505','55000','25001'):
                raise PrincipalProvisionError('PRINCIPAL_PROVISION_REJECTED') from None
            raise PrincipalProvisionError('PRINCIPAL_BACKEND_UNAVAILABLE') from None
        except Exception:
            # Connection/commit/reset ambiguity never becomes success or automatic
            # replay. A new explicit verified request may resolve the same account.
            raise PrincipalProvisionError('PRINCIPAL_BACKEND_UNAVAILABLE') from None
        return receipt  # Only after transaction commit and pool reset have succeeded.
