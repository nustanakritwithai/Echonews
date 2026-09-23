# WEB-PREVIEW-01 — Echo Voice Room

## One task
Deliver the previously requested interactive GitHub Pages preview in `nustanakritwithai/Echonews`. This is a separate, synthetic UI experiment; it does not advance the unverified backend gates.

## Created
Static event feed and rooms, original voices, Reality/Society separation, curated evidence references and timelines, local-only draft/opt-in/withdraw/delete, search and follow views. All fixture content is fictional. Selection and voice typing are manual. There is no running LLM or backend.

## Verification locally
- Node core tests: 32/32 SAT.
- Offline Chromium DOM smoke assertions: 21/21 SAT; in-memory test Storage, bundled scripts, no HTTP and no CSP/module loading verification.
- Real HTTP Chromium suite: prepared with 12 cases, initially BLOCKED_ENVIRONMENT locally (`ERR_BLOCKED_BY_ADMINISTRATOR` opening local HTTP). Do not count as 12 app failures or passes. GitHub Actions runs the actual HTTP suite in its runner.
- Reviewed mobile and desktop screenshots from the offline renderer.
- Live Pages: not assumed from pushing code; inspect Actions deployment status.

## Existing backend gates unchanged
P2.1 SQLite reference and P2.1b PostgreSQL proposal are distinct artifacts; do not apply SQLite SQL as PostgreSQL. P2.1b runtime, authenticated review, permissions, immutable mutation rules and snapshot admission are still unfinished. No user database or cloud service has been modified for this preview.

## Next
First verify CI and Pages deployment. Then resume P2.1b-runtime on an isolated PostgreSQL database before connecting any real users or public reporting. Preserve local-only labeling until an authenticated backend and cross-layer privacy checks pass.
