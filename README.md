# Echo News Center

**หนึ่งเหตุการณ์ หลายเสียง ทุกเสียงมีที่มา**

Mobile-first event-centric social news research preview.

**Website:** https://nustanakritwithai.github.io/Echonews/

## Try it

Open a room from the event feed, select an orbit group, inspect an original voice, or open a claim to see its supporting and opposing references. Use **เพิ่มเสียง** to try creating a local post linked to a room. Posts remain visible in **เสียงของฉัน**. Unlinked posts are excluded from room views, counts and search.

## Important limits

All bundled events, people, evidence and places are fictional. This is NOT a live news service, emergency information source, AI fact-checker or multi-user social network yet.

Posts, new rooms and followed rooms are stored only in the visitor's browser. They are not published to other people. Do not enter sensitive information. Local UI visibility is not server authorization. The earlier P2.1 Python/SQLite reference backend is not deployed by this repository.

New voices do not automatically change claim status. Copies sharing a known evidence family do not increase independent-source counts. Source independence and current freshness are not inferred by this preview.

## Development

No npm dependencies or build step are required for the frontend.

```bash
npm run check
npm test
python -m http.server 8000
```

For browser tests:

```bash
python -m pip install playwright==1.56.0
python -m playwright install --with-deps chromium
python tests/browser_smoke.py
```

## Verification and deployment

GitHub Actions tests JavaScript and 28 core invariants, then runs 31 browser interaction/responsive checks against repository assets served at a synthetic HTTPS origin. On success it deploys a whitelist of static frontend files to Pages and checks the real published HTTPS assets against the tested source using SHA-256.

The browser checks cover module loading, CSP, native localStorage, follow/reload, composer, room creation, privacy-like UI filtering, source inspection, withdrawal/reset and widths 360/390/768/1440. They are not a production security audit or live-data verification. Post-deployment HTTP/hash checks are separate from browser tests.

See [preview scope and next dependencies](docs/WEB_PREVIEW.md). Authentication, API permissions, durable workers, real reporting and AI evaluation remain future work.
