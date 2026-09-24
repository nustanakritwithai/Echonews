"""c5c.5b.2 internal boundary; no refresh token, HTTP route or client-selected ids.
Uses the existing signed verifier and issuer-bound session-key derivation.
"""
from dataclasses import dataclass
from typing import Callable
import psycopg
from identity_boundary import Config, _json_object
from account_link_boundary import _strict_signed_identity, _ms, SignedAccountLinkError
from postgres_registry_adapter import derive_session_key

POLICY = 'MONOTONIC_SIGNED_BEARER_ROTATION_V1'
ROTATE_SQL = 'SELECT echo_identity.runtime_rotate_active_session(%s,%s,%s,%s,%s,%s)'
CLOCK_SQL = 'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint'
MAX_MS = 9007199254740991


class SessionRotationError(Exception):
    def __init__(self,code: str):
        self.code=code
        super().__init__(code)


@dataclass(frozen=True)
class SessionRotationReceipt:
    auth_version: int
    expires_at_ms: int
    replayed: bool


class SignedSessionRotationBoundary:
    def __init__(self,config: Config,connect_runtime: Callable[[],object]):
        if type(config) is not Config or not callable(connect_runtime):
            raise ValueError('trusted config and transaction-owning pool required')
        self._config=config
        self._connect_runtime=connect_runtime

    def rotate(self,authorization: str | None,raw_body: bytes) -> SessionRotationReceipt:
        try:
            body=_json_object(raw_body,256)
            if body:
                raise ValueError('only an empty object is accepted')
        except (ValueError,TypeError,KeyError,RecursionError):
            raise SessionRotationError('INVALID_ROTATION_REQUEST') from None
        try:
            claims=_strict_signed_identity(self._config,authorization)
            if len(claims['sub'])>255:
                raise ValueError('outside durable subject profile')
            key=derive_session_key(self._config.issuer,claims['jti'])
            issued,not_before,expires=(_ms(claims[k]) for k in ('iat','nbf','exp'))
        except (SignedAccountLinkError,ValueError,TypeError,KeyError):
            raise SessionRotationError('IDENTITY_REJECTED') from None
        try:
            with self._connect_runtime() as c:
                row=c.execute(ROTATE_SQL,(self._config.issuer,claims['sub'],key,issued,not_before,expires)).fetchone()
                if row is None or len(row)!=1 or type(row[0]) is not dict:
                    raise SessionRotationError('ROTATION_CONTRACT_VIOLATION')
                r=row[0]
                if set(r)!={'sessionKey','issuer','subject','authVersion','issuedAtMs','expiresAtMs',
                           'authorizedUntilMs','replayed','policy'}:
                    raise SessionRotationError('ROTATION_CONTRACT_VIOLATION')
                if (r['sessionKey']!=key or r['issuer']!=self._config.issuer or r['subject']!=claims['sub']
                        or r['policy']!=POLICY or type(r['authVersion']) is not int
                        or not 2<=r['authVersion']<=2147483647 or type(r['replayed']) is not bool
                        or type(r['issuedAtMs']) is not int or r['issuedAtMs']!=issued
                        or type(r['expiresAtMs']) is not int or r['expiresAtMs']!=expires
                        or type(r['authorizedUntilMs']) is not int
                        or not issued<r['authorizedUntilMs']<=expires):
                    raise SessionRotationError('ROTATION_CONTRACT_VIOLATION')
                clock=c.execute(CLOCK_SQL).fetchone()
                if clock is None or len(clock)!=1 or type(clock[0]) is not int or not 0<=clock[0]<=MAX_MS:
                    raise SessionRotationError('ROTATION_CONTRACT_VIOLATION')
                if clock[0]<issued or clock[0]<not_before or clock[0]>=r['authorizedUntilMs']:
                    raise SessionRotationError('ROTATION_REJECTED')
                receipt=SessionRotationReceipt(r['authVersion'],expires,r['replayed'])
        except SessionRotationError:
            raise
        except psycopg.Error as error:
            if error.sqlstate=='P0002':
                raise SessionRotationError('ROTATION_NO_ACTIVE_USE_REPEAT_LOGIN') from None
            if error.sqlstate in ('22023','23514','23505','55000','25001','42501'):
                raise SessionRotationError('ROTATION_REJECTED') from None
            raise SessionRotationError('ROTATION_BACKEND_UNAVAILABLE') from None
        except Exception:
            # Unknown commit/reset acknowledgement is not evidence of rollback.
            # No automatic mutation replay: explicit same-Bearer retry is separate.
            raise SessionRotationError('ROTATION_BACKEND_UNAVAILABLE') from None
        return receipt  # Only after the owning pool commits and resets successfully.
