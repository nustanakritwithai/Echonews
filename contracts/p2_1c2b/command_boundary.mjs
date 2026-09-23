// Echo News P2.1c.2b — trusted writer/reviewer command boundary.
// This module is deliberately backend-neutral. It binds already-authenticated
// server context to commands and rejects client attempts to supply identity.
// It does NOT authenticate tokens, write PostgreSQL, link rooms, or publish data.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VOICE_KEYS = new Set(['content', 'visibility']);
const REVIEW_KEYS = new Set(['assessmentId', 'expectedRevision', 'decision', 'rationale']);
const VOICE_VISIBILITY = new Set(['PRIVATE', 'PUBLIC']);
const REVIEW_DECISIONS = new Set(['ACCEPTED', 'REJECTED']);

function fail(message) { throw new Error(message); }
function plain(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail(`${label} must be a plain object`);
  return value;
}
function exactKeys(value, allowed, label) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${label} field not allowed: ${key}`);
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) fail(`${label} must be a UUID`);
  return value;
}
function text(value, label, max) {
  if (typeof value !== 'string' || !value.trim()) fail(`${label} is required`);
  if ([...value].length > max) fail(`${label} exceeds ${max} characters`);
  return value;
}
function trustedAuth(auth) {
  plain(auth, 'auth');
  if (auth.trusted !== true || auth.authenticated !== true) fail('trusted authenticated server context required');
  uuid(auth.actorId, 'auth.actorId');
  uuid(auth.sourceId, 'auth.sourceId');
  if (!['HUMAN', 'AI', 'SYSTEM'].includes(auth.actorKind)) fail('auth.actorKind is invalid');
  if (!Array.isArray(auth.roles) || auth.roles.some(r => typeof r !== 'string')) fail('auth.roles must be an array');
  return auth;
}
function serverDeps(server) {
  plain(server, 'server');
  if (typeof server.newUuid !== 'function' || typeof server.now !== 'function' || typeof server.storePayload !== 'function') {
    fail('trusted server dependencies required');
  }
  return server;
}
function requireRole(auth, role) {
  if (!auth.roles.includes(role)) fail(`${role} role required`);
}
function serverNow(server) {
  const value = server.now();
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) fail('server.now() returned invalid time');
  return value;
}

export function bindCreateVoice(body, authContext, serverContext) {
  const request = plain(body, 'voice request');
  exactKeys(request, VOICE_KEYS, 'voice request');
  const auth = trustedAuth(authContext);
  requireRole(auth, 'writer');
  if (auth.actorKind !== 'HUMAN') fail('human writer required');
  const server = serverDeps(serverContext);
  const content = text(request.content, 'content', 2000);
  const visibility = request.visibility ?? 'PRIVATE';
  if (!VOICE_VISIBILITY.has(visibility)) fail('visibility must be PRIVATE or PUBLIC');
  const voiceId = uuid(server.newUuid(), 'server voice id');
  const payloadRef = server.storePayload(content);
  if (typeof payloadRef !== 'string' || !payloadRef.trim()) fail('server payload reference is invalid');
  const now = serverNow(server);
  return Object.freeze({
    commandKind: 'CREATE_VOICE_REVISION',
    voiceId,
    revision: 1,
    previousRevision: null,
    authorId: auth.actorId,
    sourceId: auth.sourceId,
    payloadRef,
    visibility,
    postedAt: now,
    recordedAt: now
  });
}

export function bindReviewAssessment(body, authContext, existingAssessment, serverContext) {
  const request = plain(body, 'review request');
  exactKeys(request, REVIEW_KEYS, 'review request');
  const auth = trustedAuth(authContext);
  requireRole(auth, 'reviewer');
  if (auth.actorKind !== 'HUMAN') fail('human reviewer required');
  const existing = plain(existingAssessment, 'existing assessment');
  const server = serverDeps(serverContext);
  uuid(request.assessmentId, 'assessmentId');
  if (request.assessmentId !== existing.assessmentId) fail('assessment target mismatch');
  if (!Number.isInteger(request.expectedRevision) || request.expectedRevision < 1) fail('expectedRevision must be a positive integer');
  if (request.expectedRevision !== existing.revision) fail('stale assessment revision');
  if (existing.reviewState !== 'PENDING' || existing.withdrawn === true) fail('assessment is not reviewable');
  if (!REVIEW_DECISIONS.has(request.decision)) fail('decision must be ACCEPTED or REJECTED');
  const rationale = text(request.rationale, 'rationale', 2000);
  const now = serverNow(server);
  return Object.freeze({
    commandKind: 'APPEND_ASSESSMENT_REVIEW',
    assessmentId: existing.assessmentId,
    revision: existing.revision + 1,
    previousRevision: existing.revision,
    eventId: existing.eventId,
    claimId: existing.claimId,
    claimRevision: existing.claimRevision,
    scopeKey: existing.scopeKey,
    evidenceId: existing.evidenceId,
    evidenceRevision: existing.evidenceRevision,
    relation: existing.relation,
    reviewState: request.decision,
    withdrawn: false,
    assessorId: auth.actorId,
    assessorKind: 'HUMAN',
    methodVersion: server.reviewMethodVersion ?? 'human-review-command-v0.1',
    rationale,
    validTimeStatus: existing.validTimeStatus,
    validFrom: existing.validFrom ?? null,
    validUntil: existing.validUntil ?? null,
    assessedAt: now,
    recordedAt: now
  });
}

export const clientVoiceFields = Object.freeze([...VOICE_KEYS]);
export const clientReviewFields = Object.freeze([...REVIEW_KEYS]);
