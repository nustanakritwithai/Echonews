# Echo News Center — Web Research Preview 0.1

## Scope

This release adds a standalone static frontend to the initially empty Echonews repository. It does not deploy or expose the earlier P2.1 SQLite reference database. PostgreSQL, auth, API, worker, external news ingestion and real claim verification remain NOT IMPLEMENTED in this web release.

All bundled events, people, observations and evidence metadata are fictional UI fixtures. None are live reports. No emergency or travel advice is provided.

## Working user flows

- Event feed, keyword search, categories and followed rooms.
- Echo Voice Room with separate fixture evidence states and societal voices.
- Interactive orbit groups for observations, questions, opinions and corrections.
- Claim -> supporting/counter references -> original voice -> evidence family.
- Original posts retained in local owner feed. Optional room linkage.
- Local post creation, local room creation, withdrawal and confirmed reset.
- LocalStorage persistence with validated input; no multi-user publishing.
- Hash routes and relative imports work under a project Pages path.

## Safety boundaries

- New voices never auto-approve or rewrite fixture claim states.
- Unlinked local voices are excluded from room views, counts and event search.
- Multiple evidence families do not establish source independence.
- No current freshness is inferred from sharing time.
- A private-looking local UI option is NOT a server authorization boundary.
- No secrets, API keys, raw databases or personal research artifacts are published.
- User text is escaped; source URLs allow only http/https and are not fetched.
- Storage is browser-local, not encrypted; do not enter sensitive information.

## Verification

`npm run check` and `npm test` validate JS syntax and 28 core invariants.

`python tests/browser_smoke.py` uses Playwright Chromium with a synthetic HTTPS origin serving repository assets by request interception. It checks original CSP/module loading, real browser localStorage, room navigation, follow/reload, composer, claim/source inspection, pending state, unlinked-post isolation, withdrawal, reset and widths 360/390/768/1440. This is NOT deployed-site browser verification or a production security audit.

Local environment also used an offline DOM-only harness with storage/UUID shims and CSS injection because managed Chromium blocked URL navigation. Its successful checks do not substitute for the CI browser checks. GitHub Actions gates Pages deployment on both core and full browser tests, and retains verification artifacts.

## Publish boundary

Only index.html, style.css, app.js, core.js, data.js, favicon.svg and .nojekyll are staged as the Pages artifact. The repository workflow uses Pages write and OIDC only in the deploy job.

## Next dependency

Connect a tested authenticated API after completing P2.2 permission/room-build/worker contracts. Do not reinterpret this UI demo as completion of those backend tasks.
