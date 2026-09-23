# echo. — Echo News Center

Mobile-first **Echo Voice Room** research preview. One event connects original human voices; it does not replace authors or treat popularity as truth.

## Scope

All initial people, places, reports, evidence and claim labels are fictional fixtures. Decorative maps are illustrations, not evidence. Do not use this preview for emergency decisions.

Implemented: event feed, search/category filters, room views, voice-type clusters, original-post inspection, evidence lineage display, fictional timelines, browser-local drafts, explicit local-room opt-in, withdrawal/deletion, local follows and an honest scope page.

No server, user accounts, live news, external scraping, automatic clustering, AI verification, real media verification, native notifications or multi-user publishing are connected. Added voices **do not change the manually curated claim labels**.

Local data is unencrypted `localStorage` on this browser/origin. Other applications on the same origin and people using this browser may access it. Do not store secrets or personal information. Drafts excluded from a room are excluded from the room's counts and search. Clearing browser data loses local posts.

## Run

```sh
python -m http.server 8000
# Open http://localhost:8000/
node --test tests/core.test.mjs
```

Real browser integration tests use Python Playwright 1.57.0:

```sh
python -m pip install playwright==1.57.0
python -m playwright install --with-deps chromium
ECHO_USE_BUNDLED_BROWSER=1 python tests/browser_test.py
```

Tests serve the real files under `/Echonews/` and check module loading, mobile/desktop overflow, source inspection, native localStorage reload, exclusion, withdrawal, HTML escaping, follow filters and error paths.

## GitHub Pages

Project path: `https://nustanakritwithai.github.io/Echonews/`.

In repository Settings → Pages choose **GitHub Actions** as the source. The included workflow runs core/browser tests before deploying the explicit static file allowlist. It does not deploy on pull requests. Hash routes and relative asset paths support the project subpath. If Pages is not enabled, the configure/deploy job will fail; a successful source commit alone is not proof the site is live.

## Research gates

This preview is the explicitly requested UI trial, **not** completion of PostgreSQL runtime or permission/verification work. P2.1b runtime remains UNKNOWN until its actual SQL tests run. Production social reporting remains blocked pending authentication, visibility propagation, evidence review, database integration, moderation and privacy tests.

See `CHECKPOINT.md` for completed/blocked/next work.
