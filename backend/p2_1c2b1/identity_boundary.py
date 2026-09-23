"""Echo P2.1c.2b.1 / P2.1c.2c.3 / P2.1c.2d.2b signed identity boundary.

NOT an HTTP server, OIDC provider, DB writer or object-level authorization grant.
The only untrusted entrypoint is Boundary.bind(authorization, raw_body).
Configuration, key selection and identity adapters are trusted backend code.
No network fetches, token logging, key minting or default production configuration.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Mapping
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

POLICY_VERSION = "echo-identity-preflight-v0.3"
CAPABILITIES = frozenset({"voice:draft:create", "assessment:review"})
ACTOR_KINDS = frozenset({"HUMAN", "AI", "SYSTEM", "TEST_FIXTURE", "UNKNOWN"})
TOKEN_LIMIT = 8192
BODY_LIMIT = 16384
_MAX_SAFE_MS = 9007199254740991
_SESSION_KEY = re.compile(r"^[a-f0-9]{64}$")


class BoundaryError(Exception):
    """Public-safe category only. Never interpolate untrusted text or tokens."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _bad_constant(_: str) -> None:
    raise ValueError("non-JSON number")


def _inspect_json(value: object, depth: int = 0) -> None:
    if depth > 8:
        raise ValueError("nested data exceeds profile")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        if "\x00" in value:
            raise ValueError("NUL is not supported")
    elif isinstance(value, dict):
        for key, item in value.items():
            _inspect_json(key, depth + 1)
            _inspect_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _inspect_json(item, depth + 1)


def _json_object(raw: bytes, limit: int) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError("invalid input size/type")
    result = json.loads(raw.decode("utf-8", errors="strict"),
                        object_pairs_hook=_pairs, parse_constant=_bad_constant)
    if type(result) is not dict:
        raise ValueError("JSON object required")
    _inspect_json(result)
    return result


def _uuid(value: object) -> UUID:
    if type(value) is not str:
        raise ValueError("UUID string required")
    parsed = UUID(value)
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("canonical, nonnil UUID required")
    return parsed


def _text(value: object, maximum: int) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise ValueError("invalid text")
    return value


def _milliseconds(seconds: int) -> int:
    if type(seconds) is not int or seconds < 0 or seconds > _MAX_SAFE_MS // 1000:
        raise ValueError("NumericDate cannot be represented safely in milliseconds")
    return seconds * 1000


@dataclass(frozen=True)
class ActorBinding:
    """Trusted registry result; never deserialize this dataclass from a request.

    Durable-registry fields principal_id/source_id/session_key are server-owned and
    must be supplied as one complete tuple. Legacy fixture adapters may omit all of
    them; such adapters can preflight but cannot mint a DB authorization stamp.
    """

    issuer: str
    subject: str
    actor_id: UUID
    actor_kind: str
    capabilities: frozenset[str]
    revision: int
    enabled: bool
    tokens_valid_from: int = 0
    source_id: UUID | None = None
    authorization_expires_at: int | None = None
    principal_id: UUID | None = None
    session_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Config:
    issuer: str
    audience: str
    key_set_version: str
    keys: Mapping[str, RSAPublicKey] = field(repr=False)
    max_lifetime_seconds: int = 900

    def __post_init__(self) -> None:
        if (type(self.issuer) is not str or not self.issuer.startswith("https://")
                or self.issuer.strip() != self.issuer
                or type(self.audience) is not str or not self.audience.strip()
                or type(self.key_set_version) is not str or not self.key_set_version.strip()
                or type(self.max_lifetime_seconds) is not int
                or not 1 <= self.max_lifetime_seconds <= 3600):
            raise ValueError("invalid trusted configuration")
        keys = dict(self.keys)
        if not keys:
            raise ValueError("explicit trusted public keys required")
        for kid, key in keys.items():
            if (type(kid) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", kid)
                    or not isinstance(key, RSAPublicKey) or key.key_size < 2048):
                raise ValueError("invalid trusted RSA public key")
        object.__setattr__(self, "keys", MappingProxyType(keys))


@dataclass(frozen=True)
class DraftIntent:
    text: str = field(repr=False)


@dataclass(frozen=True)
class ReviewIntent:
    assessment_id: UUID
    expected_revision: int
    decision: str
    rationale: str = field(repr=False)


@dataclass(frozen=True)
class AuthorizationStamp:
    """Server-owned authorization context for a later same-transaction DB fence.

    This object is not a bearer token and never proves authorization by itself. The
    database MUST recheck current authority/session state before any guarded write.
    """

    issuer: str = field(repr=False)
    subject: str = field(repr=False)
    session_key: str = field(repr=False)
    principal_id: UUID
    actor_id: UUID
    source_id: UUID
    auth_version: int
    capability: str
    token_issued_ms: int
    token_not_before_ms: int
    token_expires_ms: int
    key_set_version: str
    policy_version: str = POLICY_VERSION

    def private_draft_fence_args(self) -> tuple[object, ...]:
        if self.capability != "voice:draft:create":
            raise ValueError("stamp is not valid for the private draft fence")
        return (self.issuer, self.subject, self.session_key, self.principal_id,
                self.actor_id, self.source_id, self.auth_version, self.capability,
                self.token_issued_ms, self.token_not_before_ms, self.token_expires_ms)


@dataclass(frozen=True)
class BoundIntent:
    """In-process preflight only. This is NOT an authorization bearer artifact."""

    request_id: UUID
    command: str
    actor_id: UUID
    actor_kind: str
    binding_revision: int
    issued_at: int
    expires_at: int
    key_set_version: str
    payload: DraftIntent | ReviewIntent
    source_id: UUID | None = None
    authorization_stamp: AuthorizationStamp | None = field(default=None, repr=False)
    policy_version: str = POLICY_VERSION

    @property
    def ready_for_execution(self) -> bool:
        return False


class Boundary:
    def __init__(self, config: Config,
                 lookup_binding: Callable[[str, str], ActorBinding | None] | None = None,
                 is_revoked: Callable[[str, str], bool] | None = None,
                 *, resolve_binding: Callable[[str, str, str], ActorBinding | None] | None = None):
        self._config = config
        self._resolve = resolve_binding
        if resolve_binding is not None:
            if not callable(resolve_binding) or lookup_binding is not None or is_revoked is not None:
                raise ValueError("atomic resolver cannot be combined with legacy adapters")
            self._lookup = None
            self._is_revoked = None
        else:
            if not callable(lookup_binding) or not callable(is_revoked):
                raise ValueError("explicit trusted adapters required")
            self._lookup = lookup_binding
            self._is_revoked = is_revoked

    def _authenticate(self, authorization: str | None) -> tuple[ActorBinding, dict, int]:
        try:
            if type(authorization) is not str or not authorization.startswith("Bearer "):
                raise ValueError("bearer header required")
            token = authorization[7:]
            if not 0 < len(token) <= TOKEN_LIMIT:
                raise ValueError("token exceeds profile")
            parts = token.split(".")
            if len(parts) != 3 or any(not re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts):
                raise ValueError("invalid compact JWS")

            def decode_json(part: str) -> dict:
                decoded = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
                return _json_object(decoded, TOKEN_LIMIT)

            header = decode_json(parts[0])
            untrusted_claims = decode_json(parts[1])
            if (set(header) != {"alg", "typ", "kid"}
                    or header["alg"] != "RS256" or header["typ"] != "at+jwt"
                    or type(header["kid"]) is not str
                    or header["kid"] not in self._config.keys):
                raise ValueError("unsupported header")
            claims = jwt.decode(
                token, self._config.keys[header["kid"]], algorithms=["RS256"],
                issuer=self._config.issuer, audience=self._config.audience,
                leeway=0,
                options={"require": ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"],
                         "verify_signature": True, "verify_exp": True,
                         "verify_nbf": True, "verify_iat": True,
                         "verify_iss": True, "verify_aud": True,
                         "verify_sub": True, "verify_jti": True, "strict_aud": True},
            )
            if claims != untrusted_claims:
                raise ValueError("parser disagreement")
            if claims["iss"] != self._config.issuer or claims["aud"] != self._config.audience:
                raise ValueError("exact issuer and audience required")
            for key in ("sub", "jti"):
                _text(claims[key], 256)
            for key in ("iat", "nbf", "exp"):
                if type(claims[key]) is not int or not 0 <= claims[key] < 2**53:
                    raise ValueError("integral NumericDate required")
                _milliseconds(claims[key])
            if not (claims["iat"] <= claims["nbf"] < claims["exp"]
                    and 0 < claims["exp"] - claims["iat"] <= self._config.max_lifetime_seconds):
                raise ValueError("invalid validity window")
        except (ValueError, TypeError, KeyError, RecursionError, binascii.Error,
                jwt.InvalidTokenError, jwt.InvalidKeyError):
            raise BoundaryError("IDENTITY_REJECTED") from None

        try:
            if self._resolve is not None:
                binding = self._resolve(self._config.issuer, claims["sub"], claims["jti"])
            else:
                revoked = self._is_revoked(self._config.issuer, claims["jti"])
                if type(revoked) is not bool:
                    raise ValueError("revocation adapter contract violation")
                binding = self._lookup(self._config.issuer, claims["sub"]) if not revoked else None
        except Exception:
            raise BoundaryError("IDENTITY_BACKEND_UNAVAILABLE") from None
        if binding is None or type(binding) is not ActorBinding:
            raise BoundaryError("IDENTITY_REJECTED")
        durable = (binding.source_id, binding.principal_id, binding.session_key)
        if any(value is not None for value in durable) and not all(value is not None for value in durable):
            raise BoundaryError("IDENTITY_REJECTED")
        if (binding.issuer != self._config.issuer or binding.subject != claims["sub"]
                or type(binding.actor_id) is not UUID or binding.actor_id.int == 0
                or type(binding.actor_kind) is not str or binding.actor_kind not in ACTOR_KINDS
                or type(binding.enabled) is not bool or not binding.enabled
                or type(binding.revision) is not int or binding.revision <= 0
                or type(binding.tokens_valid_from) is not int or binding.tokens_valid_from < 0
                or type(binding.capabilities) is not frozenset
                or not binding.capabilities <= CAPABILITIES
                or (binding.source_id is not None
                    and (type(binding.source_id) is not UUID or binding.source_id.int == 0))
                or (binding.principal_id is not None
                    and (type(binding.principal_id) is not UUID or binding.principal_id.int == 0))
                or (binding.session_key is not None
                    and (type(binding.session_key) is not str
                         or _SESSION_KEY.fullmatch(binding.session_key) is None))
                or (binding.authorization_expires_at is not None
                    and (type(binding.authorization_expires_at) is not int
                         or binding.authorization_expires_at <= 0))
                or claims["iat"] < binding.tokens_valid_from):
            raise BoundaryError("IDENTITY_REJECTED")
        effective_exp = claims["exp"]
        if binding.authorization_expires_at is not None:
            effective_exp = min(effective_exp, binding.authorization_expires_at)
        if effective_exp <= claims["iat"]:
            raise BoundaryError("IDENTITY_REJECTED")
        return binding, claims, effective_exp

    def bind(self, authorization: str | None, raw_body: bytes) -> BoundIntent:
        """Bind verified identity/capability only; target authorization is pending."""
        binding, claims, effective_exp = self._authenticate(authorization)
        try:
            request = _json_object(raw_body, BODY_LIMIT)
            if set(request) != {"request_id", "command", "payload"}:
                raise ValueError("unknown or missing command member")
            request_id = _uuid(request["request_id"])
            command = request["command"]
            payload = request["payload"]
            if type(payload) is not dict:
                raise ValueError("payload object required")
            if command == "CREATE_VOICE_DRAFT":
                if set(payload) != {"text"}:
                    raise ValueError("draft payload fields")
                parsed: DraftIntent | ReviewIntent = DraftIntent(_text(payload["text"], 2000))
                capability = "voice:draft:create"
            elif command == "REVIEW_EVIDENCE_RELATION":
                if set(payload) != {"assessment_id", "expected_revision", "decision", "rationale"}:
                    raise ValueError("review payload fields")
                rev = payload["expected_revision"]
                if type(rev) is not int or not 1 <= rev <= 2147483647:
                    raise ValueError("revision required")
                if payload["decision"] not in ("ACCEPTED", "REJECTED"):
                    raise ValueError("decision required")
                parsed = ReviewIntent(_uuid(payload["assessment_id"]), rev,
                                      payload["decision"], _text(payload["rationale"], 1000))
                capability = "assessment:review"
            else:
                raise ValueError("unknown command")
        except (ValueError, TypeError, KeyError, RecursionError):
            raise BoundaryError("INVALID_COMMAND") from None
        if capability not in binding.capabilities:
            raise BoundaryError("CAPABILITY_REQUIRED")
        if command == "REVIEW_EVIDENCE_RELATION" and binding.actor_kind != "HUMAN":
            raise BoundaryError("HUMAN_REVIEW_REQUIRED")

        stamp = None
        if (binding.source_id is not None and binding.principal_id is not None
                and binding.session_key is not None):
            stamp = AuthorizationStamp(
                issuer=binding.issuer, subject=binding.subject,
                session_key=binding.session_key, principal_id=binding.principal_id,
                actor_id=binding.actor_id, source_id=binding.source_id,
                auth_version=binding.revision, capability=capability,
                token_issued_ms=_milliseconds(claims["iat"]),
                token_not_before_ms=_milliseconds(claims["nbf"]),
                token_expires_ms=_milliseconds(claims["exp"]),
                key_set_version=self._config.key_set_version,
            )
        return BoundIntent(request_id=request_id, command=command,
                           actor_id=binding.actor_id, actor_kind=binding.actor_kind,
                           binding_revision=binding.revision, issued_at=claims["iat"],
                           expires_at=effective_exp, key_set_version=self._config.key_set_version,
                           payload=parsed, source_id=binding.source_id,
                           authorization_stamp=stamp)
