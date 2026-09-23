// P2.1c.2c — trusted credential result -> current durable identity/session -> auth.
// SERVER INTERNAL. This is NOT a JWT/opaque-token verifier, HTTP endpoint, cache,
// database write adapter, or a revocation fence for a later transaction commit.
// Call again for EVERY command. The store callback must read a consistent primary
// snapshot. Real verifier and provisioning adapters remain separate release gates.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY = /^[a-f0-9]{64}$/;
const CAPABILITIES = new Set(['writer', 'reviewer']);

export class SessionBoundaryError extends Error {
  constructor(code) { super(code); this.name = 'SessionBoundaryError'; this.code = code; }
}
const deny = (code = 'UNAUTHENTICATED') => { throw new SessionBoundaryError(code); };
function object(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) deny();
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) deny();
  return v;
}
function string(v, max) {
  if (typeof v !== 'string' || v.length === 0 || [...v].length > max || /[\x00-\x1f\x7f]/.test(v)) deny();
  return v; // Do NOT trim, lowercase or otherwise merge distinct identities.
}
function uuid(v) { if (typeof v !== 'string' || !UUID.test(v)) deny(); return v; }
function integer(v) { if (!Number.isSafeInteger(v) || v < 0) deny(); return v; }
function version(v) { integer(v); if (v < 1 || v > 2147483647) deny(); return v; }
function boolean(v) { if (typeof v !== 'boolean') deny(); return v; }
function sessionKey(v) { if (typeof v !== 'string' || !KEY.test(v)) deny(); return v; }
function checkedClock(now) {
  let value;
  try { value = now(); } catch { deny('AUTHORITY_UNAVAILABLE'); }
  if (!Number.isSafeInteger(value) || value < 0) deny('AUTHORITY_UNAVAILABLE');
  return value;
}
function verifiedResult(raw, issuer, audience) {
  const r = object(raw);
  if (r.tokenUse !== 'ECHO_API_ACCESS') deny(); // Not a general OIDC ID-token API.
  if (string(r.issuer, 2048) !== issuer) deny();
  if (!Array.isArray(r.audiences) || r.audiences.length === 0 || r.audiences.length > 16) deny();
  const audiences = r.audiences.map(a => string(a, 2048));
  if (!audiences.includes(audience)) deny();
  const result = {
    issuer, subject: string(r.subject, 255), sessionKey: sessionKey(r.sessionKey),
    issuedAtMs: integer(r.issuedAtMs), notBeforeMs: integer(r.notBeforeMs),
    expiresAtMs: integer(r.expiresAtMs)
  };
  if (result.expiresAtMs <= result.issuedAtMs || result.expiresAtMs <= result.notBeforeMs) deny();
  // Role/actor/email/name/token fields from verifier are intentionally NOT copied.
  return Object.freeze(result);
}
function tokenValidAt(v, time) {
  if (time < v.issuedAtMs || time < v.notBeforeMs || time >= v.expiresAtMs) deny();
}
function currentBinding(raw, v, capability, checkedAtMs) {
  const snapshot = object(raw), p = object(snapshot.principal), s = object(snapshot.session);
  const principalId = uuid(p.principalId), actorId = uuid(p.actorId), sourceId = uuid(p.sourceId);
  const authVersion = version(p.authVersion);
  if (p.actorKind !== 'HUMAN' || !boolean(p.enabled)) deny();
  if (string(p.issuer, 2048) !== v.issuer || string(p.subject, 255) !== v.subject) deny();
  if (uuid(s.principalId) !== principalId || sessionKey(s.sessionKey) !== v.sessionKey) deny();
  if (version(s.authVersion) !== authVersion || boolean(s.revoked)) deny();
  const issuedAtMs = integer(s.issuedAtMs), expiresAtMs = integer(s.expiresAtMs);
  if (expiresAtMs <= issuedAtMs || checkedAtMs < issuedAtMs || checkedAtMs >= expiresAtMs) deny();
  const writer = boolean(p.writerEnabled), reviewer = boolean(p.reviewerEnabled);
  if ((capability === 'writer' && !writer) || (capability === 'reviewer' && !reviewer)) deny('FORBIDDEN');
  const roles = Object.freeze([...(writer ? ['writer'] : []), ...(reviewer ? ['reviewer'] : [])]);
  return Object.freeze({
    trusted: true, authenticated: true, actorId, sourceId, actorKind: 'HUMAN', roles,
    authorizationStamp: Object.freeze({
      principalId, sessionKey: v.sessionKey, authVersion, checkedAtMs,
      expiresAtMs: Math.min(v.expiresAtMs, expiresAtMs), capability
    })
  });
}

export function createSessionResolver({ issuer, audience, verifyCredential, loadSnapshot, now }) {
  // Configuration and callbacks are installed by the backend, NEVER request JSON.
  string(issuer, 2048); string(audience, 2048);
  let url;
  try { url = new URL(issuer); } catch { throw new TypeError('invalid issuer configuration'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || /\s/.test(issuer)) {
    throw new TypeError('issuer must be a fixed HTTPS URL without query, credentials or fragment');
  }
  if ([verifyCredential, loadSnapshot, now].some(f => typeof f !== 'function')) {
    throw new TypeError('trusted verifier, authoritative store and clock callbacks required');
  }
  return async function resolveSession(credential, capability) {
    if (!CAPABILITIES.has(capability)) deny('FORBIDDEN');
    if (typeof credential !== 'string' || !credential || credential.length > 16384 || /\s/.test(credential)) deny();
    const startedAtMs = checkedClock(now);
    let raw;
    try {
      raw = await verifyCredential(credential, Object.freeze({issuer, audience, nowMs: startedAtMs}));
    } catch { deny(); } // No raw credential/exception text escapes this boundary.
    const v = verifiedResult(raw, issuer, audience);
    const afterVerifierMs = checkedClock(now);
    if (afterVerifierMs < startedAtMs) deny('AUTHORITY_UNAVAILABLE');
    tokenValidAt(v, afterVerifierMs);
    let snapshot;
    try {
      snapshot = await loadSnapshot(Object.freeze({issuer: v.issuer, subject: v.subject, sessionKey: v.sessionKey}));
    } catch { deny('AUTHORITY_UNAVAILABLE'); } // Never reuse a stale fallback on outage.
    const checkedAtMs = checkedClock(now);
    if (checkedAtMs < afterVerifierMs) deny('AUTHORITY_UNAVAILABLE');
    tokenValidAt(v, checkedAtMs); // A slow lookup may cross the credential expiry.
    return currentBinding(snapshot, v, capability, checkedAtMs);
  };
}
