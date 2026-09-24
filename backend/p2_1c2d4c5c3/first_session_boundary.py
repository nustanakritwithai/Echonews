"""Signed first-session bootstrap boundary for Echo News c5c.3.

This is backend code, not an HTTP route. The caller supplies only a verified bearer
credential plus an empty JSON object. Principal/Actor/Source/session identifiers are
never accepted from request data.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import psycopg

from identity_boundary import Config, _json_object
from account_link_boundary import _strict_signed_identity, _ms, SignedAccountLinkError
from postgres_registry_adapter import derive_session_key

BOOTSTRAP_SQL = "SELECT echo_identity.runtime_bootstrap_first_session(%s,%s,%s,%s,%s,%s)"
CLOCK_SQL = "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
_MAX_BODY = 256
_MAX_SAFE_MS = 9007199254740991


class FirstSessionError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class FirstSessionReceipt:
    auth_version: int
    expires_at_ms: int
    replayed: bool


class SignedFirstSessionBoundary:
    def __init__(self, config: Config, connect_runtime: Callable[[], object]):
        if type(config) is not Config or not callable(connect_runtime):
            raise ValueError("trusted config and pool required")
        self._config = config
        self._connect_runtime = connect_runtime

    def bootstrap(self, authorization: str | None, raw_body: bytes) -> FirstSessionReceipt:
        try:
            body = _json_object(raw_body, _MAX_BODY)
            if body:
                raise ValueError("empty object required")
        except (ValueError, TypeError, KeyError, RecursionError):
            raise FirstSessionError("INVALID_FIRST_SESSION_REQUEST") from None

        try:
            claims = _strict_signed_identity(self._config, authorization)
        except SignedAccountLinkError:
            raise FirstSessionError("IDENTITY_REJECTED") from None
        if len(claims["sub"]) > 255:
            raise FirstSessionError("IDENTITY_REJECTED")

        try:
            session_key = derive_session_key(self._config.issuer, claims["jti"])
            issued_ms = _ms(claims["iat"])
            not_before_ms = _ms(claims["nbf"])
            expires_ms = _ms(claims["exp"])
        except (ValueError, TypeError, KeyError):
            raise FirstSessionError("IDENTITY_REJECTED") from None

        try:
            with self._connect_runtime() as c:
                row = c.execute(BOOTSTRAP_SQL, (
                    self._config.issuer, claims["sub"], session_key,
                    issued_ms, not_before_ms, expires_ms,
                )).fetchone()
                if row is None or len(row) != 1 or type(row[0]) is not dict:
                    raise FirstSessionError("FIRST_SESSION_CONTRACT_VIOLATION")
                value = row[0]
                expected = {"sessionKey","issuer","subject","authVersion","issuedAtMs","expiresAtMs","replayed"}
                if set(value) != expected:
                    raise FirstSessionError("FIRST_SESSION_CONTRACT_VIOLATION")
                if (value["sessionKey"] != session_key or value["issuer"] != self._config.issuer
                        or value["subject"] != claims["sub"] or value["authVersion"] != 2
                        or value["issuedAtMs"] != issued_ms or value["expiresAtMs"] != expires_ms
                        or type(value["replayed"]) is not bool):
                    raise FirstSessionError("FIRST_SESSION_CONTRACT_VIOLATION")
                clock = c.execute(CLOCK_SQL).fetchone()
                if clock is None or len(clock) != 1 or type(clock[0]) is not int or not 0 <= clock[0] <= _MAX_SAFE_MS:
                    raise FirstSessionError("FIRST_SESSION_CONTRACT_VIOLATION")
                if clock[0] < issued_ms or clock[0] < not_before_ms or clock[0] >= expires_ms:
                    raise FirstSessionError("IDENTITY_REJECTED")
                receipt = FirstSessionReceipt(2, expires_ms, value["replayed"])
        except FirstSessionError:
            raise
        except psycopg.Error as error:
            if error.sqlstate in ("22023","23514","23505","55000","25001","40001","42501","P0002"):
                raise FirstSessionError("FIRST_SESSION_REJECTED") from None
            raise FirstSessionError("FIRST_SESSION_BACKEND_UNAVAILABLE") from None
        except Exception:
            raise FirstSessionError("FIRST_SESSION_BACKEND_UNAVAILABLE") from None
        return receipt
