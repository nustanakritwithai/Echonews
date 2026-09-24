"""Signed repeat-login boundary for Echo News c5c.5a.

This is backend-only and deliberately does NOT refresh an active session. The
untrusted caller supplies one signed bearer plus an empty JSON object. Identity and
session key are derived only from verified claims.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import psycopg

from identity_boundary import Config, _json_object
from account_link_boundary import _strict_signed_identity, _ms, SignedAccountLinkError
from postgres_registry_adapter import derive_session_key

REPEAT_LOGIN_SQL = "SELECT echo_identity.runtime_repeat_login_session(%s,%s,%s,%s,%s,%s)"
CLOCK_SQL = "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
_MAX_BODY = 256
_MAX_SAFE_MS = 9007199254740991


class RepeatLoginError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RepeatLoginReceipt:
    auth_version: int
    expires_at_ms: int
    replayed: bool


class SignedRepeatLoginBoundary:
    def __init__(self, config: Config, connect_runtime: Callable[[], object]):
        if type(config) is not Config or not callable(connect_runtime):
            raise ValueError("trusted config and repeat-login pool required")
        self._config = config
        self._connect_runtime = connect_runtime

    def login(self, authorization: str | None, raw_body: bytes) -> RepeatLoginReceipt:
        try:
            body = _json_object(raw_body, _MAX_BODY)
            if body:
                raise ValueError("empty object required")
        except (ValueError, TypeError, KeyError, RecursionError):
            raise RepeatLoginError("INVALID_REPEAT_LOGIN_REQUEST") from None

        try:
            claims = _strict_signed_identity(self._config, authorization)
        except SignedAccountLinkError:
            raise RepeatLoginError("IDENTITY_REJECTED") from None
        if len(claims["sub"]) > 255:
            raise RepeatLoginError("IDENTITY_REJECTED")

        try:
            session_key = derive_session_key(self._config.issuer, claims["jti"])
            issued_ms = _ms(claims["iat"])
            not_before_ms = _ms(claims["nbf"])
            expires_ms = _ms(claims["exp"])
        except (ValueError, TypeError, KeyError):
            raise RepeatLoginError("IDENTITY_REJECTED") from None

        try:
            with self._connect_runtime() as c:
                row = c.execute(REPEAT_LOGIN_SQL, (
                    self._config.issuer, claims["sub"], session_key,
                    issued_ms, not_before_ms, expires_ms,
                )).fetchone()
                if row is None or len(row) != 1 or type(row[0]) is not dict:
                    raise RepeatLoginError("REPEAT_LOGIN_CONTRACT_VIOLATION")
                value = row[0]
                expected = {
                    "sessionKey","issuer","subject","authVersion","issuedAtMs",
                    "expiresAtMs","replayed","policy",
                }
                if set(value) != expected:
                    raise RepeatLoginError("REPEAT_LOGIN_CONTRACT_VIOLATION")
                if (value["sessionKey"] != session_key
                        or value["issuer"] != self._config.issuer
                        or value["subject"] != claims["sub"]
                        or type(value["authVersion"]) is not int
                        or value["authVersion"] < 2
                        or value["issuedAtMs"] != issued_ms
                        or value["expiresAtMs"] != expires_ms
                        or type(value["replayed"]) is not bool
                        or value["policy"] != "SINGLE_ACTIVE_CURRENT_GENERATION_V1"):
                    raise RepeatLoginError("REPEAT_LOGIN_CONTRACT_VIOLATION")
                clock = c.execute(CLOCK_SQL).fetchone()
                if (clock is None or len(clock) != 1 or type(clock[0]) is not int
                        or not 0 <= clock[0] <= _MAX_SAFE_MS):
                    raise RepeatLoginError("REPEAT_LOGIN_CONTRACT_VIOLATION")
                if clock[0] < issued_ms or clock[0] < not_before_ms or clock[0] >= expires_ms:
                    raise RepeatLoginError("IDENTITY_REJECTED")
                receipt = RepeatLoginReceipt(
                    value["authVersion"], expires_ms, value["replayed"]
                )
        except RepeatLoginError:
            raise
        except psycopg.Error as error:
            if error.sqlstate in (
                "22023","23514","23505","55000","25001","40001","42501","P0002"
            ):
                raise RepeatLoginError("REPEAT_LOGIN_REJECTED") from None
            raise RepeatLoginError("REPEAT_LOGIN_BACKEND_UNAVAILABLE") from None
        except Exception:
            raise RepeatLoginError("REPEAT_LOGIN_BACKEND_UNAVAILABLE") from None
        return receipt
