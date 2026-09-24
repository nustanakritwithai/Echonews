"""Signed current-session logout; internal backend boundary, NOT HTTP.
Only the bearer token plus raw {} is accepted. No arbitrary session/Principal id.
"""
from dataclasses import dataclass
from typing import Callable

import psycopg

from identity_boundary import Config, _json_object
from account_link_boundary import _strict_signed_identity, _ms, SignedAccountLinkError
from postgres_registry_adapter import derive_session_key

LOGOUT_SQL = 'SELECT echo_identity.runtime_logout_current_session(%s,%s,%s,%s,%s,%s)'
CLOCK_SQL = 'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint'
MAX_MS = 9007199254740991


class SessionLogoutError(Exception):
    """Stable category only. Never emit bearer/claims/DSN/SQL exception details."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LogoutReceipt:
    revoked: bool


class SignedSessionLogoutBoundary:
    def __init__(self, config: Config, connect_runtime: Callable[[], object]):
        if type(config) is not Config or not callable(connect_runtime):
            raise ValueError('trusted config and transaction-owning pool required')
        self._config = config
        self._connect_runtime = connect_runtime

    def logout(self, authorization: str | None, raw_body: bytes) -> LogoutReceipt:
        try:
            body = _json_object(raw_body,256)
            if body:
                raise ValueError('empty object required')
        except (ValueError,TypeError,KeyError,RecursionError):
            raise SessionLogoutError('INVALID_LOGOUT_REQUEST') from None
        try:
            claims = _strict_signed_identity(self._config,authorization)
            if len(claims['sub']) > 255:
                raise ValueError('outside durable subject profile')
            key = derive_session_key(self._config.issuer,claims['jti'])
            issued,not_before,expires = (_ms(claims[k]) for k in ('iat','nbf','exp'))
        except (SignedAccountLinkError,ValueError,TypeError,KeyError):
            raise SessionLogoutError('IDENTITY_REJECTED') from None

        try:
            with self._connect_runtime() as c:
                row = c.execute(LOGOUT_SQL,(self._config.issuer,claims['sub'],key,
                                           issued,not_before,expires)).fetchone()
                if row is None or len(row) != 1 or type(row[0]) is not dict:
                    raise SessionLogoutError('LOGOUT_CONTRACT_VIOLATION')
                result = row[0]
                if (set(result) != {'sessionKey','revoked'} or result['sessionKey'] != key
                        or result['revoked'] is not True):
                    raise SessionLogoutError('LOGOUT_CONTRACT_VIOLATION')
                # Validate before commit, not after leaving the transaction.
                clock = c.execute(CLOCK_SQL).fetchone()
                if clock is None or len(clock) != 1 or type(clock[0]) is not int or not 0 <= clock[0] <= MAX_MS:
                    raise SessionLogoutError('LOGOUT_CONTRACT_VIOLATION')
                if clock[0] < issued or clock[0] < not_before or clock[0] >= expires:
                    raise SessionLogoutError('IDENTITY_REJECTED')
                receipt = LogoutReceipt(revoked=True)
        except SessionLogoutError:
            raise
        except psycopg.Error as error:
            if error.sqlstate in ('22023','23514','23505','55000','25001','40001','42501','P0002'):
                raise SessionLogoutError('LOGOUT_REJECTED') from None
            raise SessionLogoutError('LOGOUT_BACKEND_UNAVAILABLE') from None
        except Exception:
            # A lost commit/reset acknowledgement is NOT proof of rollback.
            # Never replay internally; a new explicit valid request is idempotent.
            raise SessionLogoutError('LOGOUT_BACKEND_UNAVAILABLE') from None
        return receipt
