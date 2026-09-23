// P2.1c.2c.3 — compose durable auth context with existing command binders.
// SERVER INTERNAL ONLY. No HTTP route, browser write path, DB writer, or public
// publication endpoint is created here.
//
// Critical semantic guard:
// - signed draft intent is NOT promoted into a generic PUBLIC writer operation.
//   This path accepts only {content} and forces PRIVATE in the existing binder.
// - reviewer capability is only a prerequisite. An explicit object-authorizer
//   callback must return true before the existing review binder can run.

import {bindCreateVoice, bindReviewAssessment} from '../p2_1c2b/command_boundary.mjs';

export class IntegratedBoundaryError extends Error {
  constructor(code) { super(code); this.name = 'IntegratedBoundaryError'; this.code = code; }
}
const reject = code => { throw new IntegratedBoundaryError(code); };

function plain(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject(label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) reject(label);
  return value;
}
function exactKeys(value, allowed, code) {
  const keys = Object.keys(value);
  if (keys.length !== allowed.size || keys.some(key => !allowed.has(key))) reject(code);
}

export function createIntegratedCommandBoundary({resolveSession, authorizeReviewObject}) {
  if (typeof resolveSession !== 'function' || typeof authorizeReviewObject !== 'function') {
    throw new TypeError('trusted session resolver and object authorizer required');
  }

  return Object.freeze({
    async bindCreateDraft(credential, body, serverContext) {
      const request = plain(body, 'INVALID_DRAFT_REQUEST');
      exactKeys(request, new Set(['content']), 'INVALID_DRAFT_REQUEST');
      const auth = await resolveSession(credential, 'writer');
      // PUBLIC is intentionally not a client option on this integration path.
      return bindCreateVoice(
        {content: request.content, visibility: 'PRIVATE'},
        auth,
        serverContext,
      );
    },

    async bindReview(credential, body, existingAssessment, serverContext) {
      const request = plain(body, 'INVALID_REVIEW_REQUEST');
      const existing = plain(existingAssessment, 'INVALID_REVIEW_OBJECT');
      const auth = await resolveSession(credential, 'reviewer');
      let allowed;
      try {
        allowed = await authorizeReviewObject(Object.freeze({
          auth,
          request,
          existingAssessment: existing,
        }));
      } catch {
        reject('OBJECT_AUTHORITY_UNAVAILABLE');
      }
      if (allowed !== true) reject('OBJECT_AUTHORIZATION_REQUIRED');
      return bindReviewAssessment(request, auth, existing, serverContext);
    },
  });
}
