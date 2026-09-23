// P2.1c.2c.3 real integration: RS256 token -> existing Python verifier ->
// durable PostgreSQL session registry -> guarded existing command binders.
// No HTTP route, browser credential, production IdP, or production DB role is used.

import test, {before, after} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {generateKeyPairSync, randomUUID, sign as rsaSign} from 'node:crypto';

import {createSessionResolver} from '../p2_1c2c/session_boundary.mjs';
import {createIntegratedCommandBoundary} from './integrated_command_boundary.mjs';

if (process.env.ECHO_DISPOSABLE_PG !== 'YES' || process.env.PGDATABASE !== 'echo_session_test' ||
    !['127.0.0.1', 'localhost'].includes(process.env.PGHOST)) {
  throw Error('Refusing destructive integration fixture outside isolated echo_session_test on loopback');
}

const ISSUER = 'https://identity.example.test';
const AUDIENCE = 'echo-api';
const KID = 'fixture-key';
const PYTHON = process.env.PYTHON || 'python';
const BRIDGE = fileURLToPath(new URL('../../backend/p2_1c2c3/verified_credential_bridge.py', import.meta.url));
const START_SEC = Math.floor(Date.now() / 1000);
const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
const PUBLIC_PEM = publicKey.export({type: 'spki', format: 'pem'}).toString();

let installed = false;

function pg(sql, params = {}) {
  const args = ['-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose'];
  for (const [key, value] of Object.entries(params)) args.push('-v', `${key}=${value}`);
  return execFileSync('psql', args, {
    input: sql, encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
}
const q = value => "'" + String(value).replaceAll("'", "''") + "'";

function b64json(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
function signedToken(overrides = {}) {
  const header = {alg: 'RS256', typ: 'at+jwt', kid: KID};
  const claims = {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: 'User-' + randomUUID(),
    iat: START_SEC - 10,
    nbf: START_SEC - 10,
    exp: START_SEC + 300,
    jti: randomUUID(),
    ...overrides,
  };
  const input = b64json(header) + '.' + b64json(claims);
  const signature = rsaSign('RSA-SHA256', Buffer.from(input, 'ascii'), privateKey).toString('base64url');
  return input + '.' + signature;
}
function bridgeVerify(credential) {
  const request = {
    credential,
    issuer: ISSUER,
    audience: AUDIENCE,
    key_set_version: 'fixture-keyset-v1',
    keys: {[KID]: PUBLIC_PEM},
  };
  const child = spawnSync(PYTHON, [BRIDGE], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    timeout: 10000,
    env: {...process.env, PYTHONHASHSEED: '0'},
  });
  if (child.status !== 0) {
    const error = new Error('VERIFIER_REJECTED');
    error.code = 'VERIFIER_REJECTED';
    throw error;
  }
  return JSON.parse(child.stdout);
}
function lookupSnapshot({issuer, subject, sessionKey}) {
  const raw = pg("SELECT echo_identity.lookup_session(:'issuer', :'subject', :'key');",
    {issuer, subject, key: sessionKey});
  return raw ? JSON.parse(raw) : null;
}
function createResolver(loadSnapshot = async lookup => lookupSnapshot(lookup)) {
  return createSessionResolver({
    issuer: ISSUER,
    audience: AUDIENCE,
    now: () => Date.now(),
    verifyCredential: async credential => bridgeVerify(credential),
    loadSnapshot,
  });
}
function serverContext() {
  return {
    newUuid: () => randomUUID(),
    storePayload: () => 'fixture:payload',
    now: () => new Date().toISOString(),
  };
}
function insertSession(principalId, token, authVersion) {
  const verified = bridgeVerify(token);
  pg(`INSERT INTO echo_identity.sessions(session_key,principal_id,auth_version,issued_at,expires_at)
      VALUES(${q(verified.sessionKey)},${q(principalId)},${authVersion},
      to_timestamp(${verified.issuedAtMs / 1000}),to_timestamp(${verified.expiresAtMs / 1000}));`);
  return verified;
}
function fixture({subject = 'User-' + randomUUID(), writer = true, reviewer = false, tokenClaims = {}} = {}) {
  const token = signedToken({sub: subject, ...tokenClaims});
  const principalId = randomUUID();
  const actorId = randomUUID();
  const sourceId = randomUUID();
  pg(`BEGIN;
    INSERT INTO echo_core.actors VALUES (${q(actorId)},'HUMAN','Synthetic signed account',now());
    INSERT INTO echo_core.sources VALUES (${q(sourceId)},'ACCOUNT',NULL,'UNKNOWN',now());
    INSERT INTO echo_identity.principals(
      principal_id,issuer,subject,actor_id,source_id,enabled,writer_enabled,reviewer_enabled)
    VALUES (${q(principalId)},${q(ISSUER)},${q(subject)},${q(actorId)},${q(sourceId)},true,${writer},${reviewer});
    COMMIT;`);
  const verified = insertSession(principalId, token, 1);
  const state = {
    token, subject, principalId, actorId, sourceId, verified,
    allowReviewObject: false,
  };
  state.resolve = createResolver();
  state.boundary = createIntegratedCommandBoundary({
    resolveSession: state.resolve,
    authorizeReviewObject: async () => state.allowReviewObject,
  });
  return state;
}
function changePrincipal(f, assignment) {
  pg(`UPDATE echo_identity.principals
      SET ${assignment}, auth_version=auth_version+1
      WHERE principal_id=${q(f.principalId)};`);
}
async function rejectsCode(fn, code) {
  await assert.rejects(fn, error => error?.code === code);
}
function assessmentFixture() {
  const assessmentId = randomUUID();
  return {
    body: {assessmentId, expectedRevision: 1, decision: 'ACCEPTED', rationale: 'Synthetic review'},
    existing: {
      assessmentId, revision: 1, reviewState: 'PENDING', withdrawn: false,
      eventId: randomUUID(), claimId: randomUUID(), claimRevision: 1,
      scopeKey: 'fixture-scope', evidenceId: randomUUID(), evidenceRevision: 1,
      relation: 'SUPPORTS', validTimeStatus: 'UNKNOWN', validFrom: null, validUntil: null,
    },
  };
}

before(() => {
  assert.equal(pg('SELECT current_database();'), 'echo_session_test');
  assert.equal(pg("SELECT to_regnamespace('echo_core') IS NULL AND to_regnamespace('echo_identity') IS NULL;"), 't');
  const base = readFileSync(new URL('../../database/p2_1b/schema.sql', import.meta.url), 'utf8');
  const migration = readFileSync(new URL('../../database/p2_1c2c/001_identity_registry.sql', import.meta.url), 'utf8');
  pg('BEGIN;\n' + base + '\n' + migration + '\nCOMMIT;');
  installed = true;
});
after(() => {
  if (!installed) return;
  pg('BEGIN; DROP SCHEMA echo_identity CASCADE; DROP SCHEMA echo_core CASCADE; COMMIT;');
  assert.equal(pg("SELECT to_regnamespace('echo_identity') IS NULL AND to_regnamespace('echo_core') IS NULL;"), 't');
  console.log('CLEAN_SIGNED_REGISTRY_DATABASE');
});

test('01 valid signed token plus current DB session binds PRIVATE draft from DB actor/source', async () => {
  const f = fixture();
  const command = await f.boundary.bindCreateDraft(f.token, {content: 'signed fixture voice'}, serverContext());
  assert.equal(command.authorId, f.actorId);
  assert.equal(command.sourceId, f.sourceId);
  assert.equal(command.visibility, 'PRIVATE');
});

test('02 committed session revocation denies the next signed request', async () => {
  const f = fixture();
  await f.resolve(f.token, 'writer');
  pg(`UPDATE echo_identity.sessions SET revoked=true WHERE session_key=${q(f.verified.sessionKey)};`);
  await rejectsCode(() => f.resolve(f.token, 'writer'), 'UNAUTHENTICATED');
});

test('03 disabled account denies an otherwise valid signed token', async () => {
  const f = fixture();
  changePrincipal(f, 'enabled=false');
  await rejectsCode(() => f.resolve(f.token, 'writer'), 'UNAUTHENTICATED');
});

test('04 stale auth_version session is denied', async () => {
  const f = fixture();
  pg(`UPDATE echo_identity.principals SET auth_version=auth_version+1 WHERE principal_id=${q(f.principalId)};`);
  await rejectsCode(() => f.resolve(f.token, 'writer'), 'UNAUTHENTICATED');
});

test('05 removed reviewer role stays removed after a fresh current-version session', async () => {
  const f = fixture({reviewer: true});
  await f.resolve(f.token, 'reviewer');
  changePrincipal(f, 'reviewer_enabled=false');
  await rejectsCode(() => f.resolve(f.token, 'reviewer'), 'UNAUTHENTICATED');
  const fresh = signedToken({sub: f.subject});
  insertSession(f.principalId, fresh, 2);
  await rejectsCode(() => f.resolve(fresh, 'reviewer'), 'FORBIDDEN');
  assert.deepEqual((await f.resolve(fresh, 'writer')).roles, ['writer']);
});

test('06 signed role or actor escalation claims do not add DB permissions', async () => {
  const claimedActor = randomUUID();
  const claimedSource = randomUUID();
  const f = fixture({tokenClaims: {
    role: 'admin', scope: 'assessment:review', actor_id: claimedActor,
    source_id: claimedSource, app_metadata: {roles: ['reviewer']},
  }});
  await rejectsCode(() => f.resolve(f.token, 'reviewer'), 'FORBIDDEN');
  const auth = await f.resolve(f.token, 'writer');
  assert.equal(auth.actorId, f.actorId);
  assert.equal(auth.sourceId, f.sourceId);
  assert.notEqual(auth.actorId, claimedActor);
  assert.notEqual(auth.sourceId, claimedSource);
});

for (const [number, label, overrides] of [
  ['07', 'wrong issuer', {iss: 'https://other.example.test'}],
  ['08', 'wrong audience', {aud: 'other-api'}],
  ['09', 'expired token', {iat: START_SEC - 100, nbf: START_SEC - 100, exp: START_SEC - 1}],
]) {
  test(`${number} ${label} is denied before any DB lookup`, async () => {
    let loads = 0;
    const resolve = createResolver(async lookup => { loads += 1; return lookupSnapshot(lookup); });
    await rejectsCode(() => resolve(signedToken(overrides), 'writer'), 'UNAUTHENTICATED');
    assert.equal(loads, 0);
  });
}

test('10 DB outage fails closed after successful cryptographic verification', async () => {
  const f = fixture();
  const resolve = createResolver(async () => { throw new Error('synthetic DB outage'); });
  await rejectsCode(() => resolve(f.token, 'writer'), 'AUTHORITY_UNAVAILABLE');
});

test('11 re-enabling an account does not revive its old token/session generation', async () => {
  const f = fixture();
  changePrincipal(f, 'enabled=false');
  changePrincipal(f, 'enabled=true');
  await rejectsCode(() => f.resolve(f.token, 'writer'), 'UNAUTHENTICATED');
  const fresh = signedToken({sub: f.subject});
  insertSession(f.principalId, fresh, 3);
  assert.equal((await f.resolve(fresh, 'writer')).actorId, f.actorId);
});

test('12 reviewer capability cannot bypass explicit object authorization', async () => {
  const f = fixture({reviewer: true});
  const {body, existing} = assessmentFixture();
  assert.equal((await f.resolve(f.token, 'reviewer')).actorId, f.actorId);
  await rejectsCode(
    () => f.boundary.bindReview(f.token, body, existing, serverContext()),
    'OBJECT_AUTHORIZATION_REQUIRED',
  );
  f.allowReviewObject = true;
  const command = await f.boundary.bindReview(f.token, body, existing, serverContext());
  assert.equal(command.assessorId, f.actorId);
  assert.equal(command.assessmentId, existing.assessmentId);
});

test('13 draft permission cannot be promoted into PUBLIC writer permission', async () => {
  const f = fixture();
  await rejectsCode(
    () => f.boundary.bindCreateDraft(
      f.token, {content: 'try publish', visibility: 'PUBLIC'}, serverContext()),
    'INVALID_DRAFT_REQUEST',
  );
  const command = await f.boundary.bindCreateDraft(f.token, {content: 'private only'}, serverContext());
  assert.equal(command.visibility, 'PRIVATE');
});

test('14 command actor/source come only from durable DB registry, never signed claims', async () => {
  const claimedActor = randomUUID();
  const claimedSource = randomUUID();
  const f = fixture({tokenClaims: {actor_id: claimedActor, source_id: claimedSource, role: 'writer'}});
  const verified = bridgeVerify(f.token);
  assert.deepEqual(Object.keys(verified).sort(), [
    'audiences', 'expiresAtMs', 'issuedAtMs', 'issuer',
    'notBeforeMs', 'sessionKey', 'subject', 'tokenUse',
  ]);
  const command = await f.boundary.bindCreateDraft(f.token, {content: 'registry owns identity'}, serverContext());
  assert.equal(command.authorId, f.actorId);
  assert.equal(command.sourceId, f.sourceId);
  assert.notEqual(command.authorId, claimedActor);
  assert.notEqual(command.sourceId, claimedSource);
});
