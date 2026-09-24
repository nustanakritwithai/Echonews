# UX-P0.1 — Event Room Header + Current State V2

One UI task from the approved Echo News UX/UI Improvement Plan. Start in `/preview/`, preserve the main frontend and all backend/database/auth work. Base main: `4b9f372f396a48358e2a1faa81ab400304ad518c`.

## Success contract
- At 360x800, the Room title, Current State, top Unknown and Reality/Society/Timeline switch are visible in the first viewport above mobile navigation.
- Supported/Disputed/Unknown have equal-weight summary cells. Counts are claim states from fixtures, never popularity or confidence scores.
- Freshness is explicitly UNKNOWN / not evaluated: fixtures do not provide trusted live freshness metadata. Latest record is labelled as the last authored timeline entry, not a live update.
- Reality is the initial panel; Society remains a separate labelled panel. Original voice, evidence drilldown, follow, draft/include/withdraw/delete and search keep working locally.
- Tabs support keyboard ArrowLeft/ArrowRight/Home/End, correct aria-selected/tabindex/panel associations and visible focus. Compact sticky context must not hide focused controls.
- No data-model/storage migration, auth integration, network write, claim inference or production-news claim. CSP and local-only warning retained.

## Verification
Native JS syntax and pure summary tests; real Chromium tests under the repository base path in CI, extending existing preview browser flows; main frontend regression unchanged. Capture 360px, desktop and sticky/panel screenshots; verify published hashes for both new static assets after deployment.

The working container blocks all Chromium URL navigation. Local layout inspection therefore uses an in-memory visual harness only; it is NOT evidence of origin/storage/CSP integration. Real served-site browser and persistence checks must run in GitHub Actions before merge. Any failures must be fixed and the final head retested.

## Limits / Next
Human comprehension within 10 seconds and >=80% Reality/Society distinction remain UNKNOWN until moderated usability testing. Automated checks are not a full accessibility certification. Future task: richer Claim/Evidence route and mobile inspector; no live publishing gate is advanced here.

Primary references for interaction: WAI-ARIA APG Tabs Pattern https://www.w3.org/WAI/ARIA/apg/patterns/tabs/ and WCAG 2.2 https://www.w3.org/TR/WCAG22/. The design uses 44px primary controls; this is our product target, not a claim that all WCAG requirements are met.
