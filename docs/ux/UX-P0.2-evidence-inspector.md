# UX-P0.2 — Claim / Evidence / Original Source Inspector

One frontend-only task after Room V2. Base main 8d5b9be019d1a0d9163ecef365808bc32dc3fba6. Preserve all backend/auth work and local storage/data contracts.

## Success contract
- Read-only Claim -> Evidence -> original Voice navigation with visible breadcrumbs and Back; keep the existing two-click Claim -> original Voice shortcut.
- Mobile bottom sheet, desktop right-side modal inspector; native dialog Escape/focus containment and return to opener. No stacked dialogs, network calls or changed evidence state.
- Evidence shows authored family grouping, time, source and scope. Family count is NOT an independence score. Original text/authorship survive; fixture external URLs are not invented.
- Unknown/missing evidence/source remains explicit; a room cannot resolve another room's records.
- Local original voices keep their text and local-only disclosure. Storage is not mutated by inspection; draft/withdraw/follow/search/compose remain covered.
- Verify mobile/desktop geometry, keyboard flow, XSS, missing data, route/storage rerenders and old Room V2 regressions. Static asset allowlist and published hashes must include the new module/CSS.

## Boundary
All sample claims/evidence/people are synthetic. No live news, live fact checking, evidence independence inference, production login or public browser writing is enabled. No claim of full WCAG certification or human usability proof from automated tests.

## Verification
Runtime UNKNOWN until the final-head native served-origin Chromium gate runs. Local container navigation may be blocked; any in-memory layout render is visual inspection only, not origin/CSP/storage evidence. Prior 24 Room V2 cases must pass without weakened assertions, alongside new inspector cases and pure scoped lookup/escaping tests.

## Next
After this gate and deployment, stop. Next UX slice: feed-level Current State/freshness/change hierarchy, while maintaining Reality/Society separation.

## Primary design references
- https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/
- https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/dialog
