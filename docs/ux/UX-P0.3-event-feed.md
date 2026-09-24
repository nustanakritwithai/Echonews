# UX-P0.3 — Evidence-first Event Feed

One approved frontend task on /preview/, based on main 887dbceccd9ee22dd4edd77a9b50c27c0d6a18c6. Preserve Room V2, Evidence Inspector, original main frontend, backend/auth/database and local-storage contracts.

## Success Contract
- Feed cards show title/place, claim-state counts, one supported claim and the leading Unknown BEFORE optional decorative imagery and Society counts.
- State counts reuse roomSummary and never derive from voice/repost/follow counts. Unknown receives equal visual weight; no supported item is not a negative or resolved verdict.
- Freshness stays UNKNOWN/not evaluated. The last authored timeline item is labelled as a fictional record, NOT a live update or inferred state change. No wall-clock recency or popularity sorting.
- Open a card's claim directly in the existing read-only inspector without changing room membership, state, storage or route. Preserve return focus and the two-click original-source path.
- Search/filter/follow/drafts/withdrawal retain their existing behavior. No login, public posting, API, CSP relaxation or storage migration.
- Native served-origin Chromium regressions and new feed checks must run on the exact final head before merge; verify published asset hashes after Pages deployment.

## Verification / boundaries
New feed unit and browser tests will cover claim-only semantics, Unknown fallback, false live freshness prevention, safe text, direct evidence entry, mobile hierarchy/reflow, unchanged private draft exclusion and state after local posts. Existing Room/Inspector tests remain unchanged and run as inherited cases once.
Local container navigation is blocked; local layout inspection is not origin/CSP/storage proof. CI is the browser integration gate. Test counts are not PASS until executed. Human comprehension and full WCAG/device coverage remain UNKNOWN.

## Next
After this feed slice passes and deploys, stop. A later UX slice can improve composer guidance and local draft/visibility labels; do not imply production multi-user publishing.
