# Daily Thailand source reports — N1

## Scope / product boundary
The user explicitly requested automatic real Thailand news every day. This slice adds `/news/`, a read-only public lane separate from synthetic Event Rooms and local user Voices. An imported article is a **source report**, not a verified Claim, independent Evidence Family, user post or automatically matched Event. Every report remains `evidenceState=UNKNOWN` and `eventMatchState=UNASSIGNED`. No signed-user/browser write permission or backend identity gate is opened.

## Schedule and deployment
`.github/workflows/pages.yml` runs at `15 1 * * *` UTC, nominally **08:15 Asia/Bangkok daily**, and on existing main pushes/manual workflow_dispatch. GitHub may delay or drop queued scheduled runs. Public-repository schedules may be disabled after 60 days without repository activity: monitor Actions and re-enable the workflow as needed. This is GitHub-hosted automation, not an on-device timer or a ChatGPT background promise.

The existing Pages pipeline is the sole publisher; no competing deployment workflow or personal access token. Default build permission stays `contents:read`; only the existing deployment job receives Pages/id-token permissions. PRs run offline fixture/unit/browser gates and never publish. A separate unprivileged source-readiness job tests the actual RSS inputs for news changes.

On main, the collector reads the **previously published** `/news/data.json` at an exact allowlisted URL, then retrieves only fixed registry feeds. A first-install HTTP404 permits bootstrap; timeout/503/corrupt previous snapshot stops deployment instead of dropping previous history. Cached source failure preserves recent records, marks the source unavailable, and never advances `lastSuccessfulFetchAt` when every source failed. If there are no recent usable records, publication stops and the old site remains live. A client-side age warning appears after 36 hours without a successful fetch even when the scheduler/build itself stopped. This is not an emergency alert service.

Source snapshot history is retained in `echo-news-build` GitHub artifacts for 30 days; the deployed view is a **rolling seven-day, maximum 240-report window**, not an indefinite immutable archive. Titles observed changing within that window append revision metadata rather than silently erasing the older observed title. Feed disappearance is not inferred to mean publisher withdrawal. Full privacy/takedown/erasure operations remain a separate gate.

## Sources and rights
Registry: `scripts/news/sources.json`. Infoquest general/politics/economy feeds were probed with actual HTTP200 RSS responses before enabling collection. These are **three feeds from one publisher**, never three independent sources. The optional Thailand.go.th Thai topics feed is a government information feed and may contain no recent entries; that condition is disclosed in source health. Only successfully parsed, dated entries within the seven-day window are eligible.

Infoquest permission reference: https://www.infoquest.co.th/using-infoquest-news-content (accessed 2026-09-24), sections1.2/1.3 permit limited link text/RSS use. This prototype keeps only headlines (maximum180 Unicode code points), publication/observation times and links. It does not copy full articles, descriptions, images, media, ads or tracking. Commercial/full-text reuse requires a separate rights review. Thailand.go.th documents RSS consumption at https://www.thailand.go.th/rss.

Thai relevance is a conservative keyword rule within selected topical feeds, plus exclusion of explicitly foreign categories. This may omit relevant reports and is not geographic fact verification. RSS endpoints expose a limited number of items: a daily run reads what is still in each feed at that moment, **not every article published that day**. No claim of complete Thai media coverage.

## Data contract / safety
- Separate `publishedAt` from firstSeenAt/lastSeenAt/generatedAt; no missing date is replaced by the fetch time. Naive, future and out-of-window dates are skipped and counted.
- Stable report ID from publisher + normalized source URL; tracking parameters/fragments removed. No semantic Event merge. Multiple feeds of one publisher deduplicate URLs while retaining feed IDs.
- A revision records observedAt, title, publishedAt and the feed-byte SHA256. The raw feed/full article is not published or persisted by the collector.
- HTTPS only, fixed source hosts/paths, default verified TLS, bounded same-host redirects, public-address check, no environment proxy, 15-second request timeout, 2MB response cap. Fixed operator endpoints only; no token-controlled or browser-supplied URLs. DNS rebinding-resistant socket pinning is not claimed.
- Reject DTD/entity declarations, malformed/non-UTF8/non-RSS XML and excessive item counts. Source text is untrusted and HTML-escaped. No publisher text becomes executable instructions, LLM input, scripts or a shell argument.
- Static rendered HTML works without JavaScript. Optional local search/source selection and age warning make no network requests or localStorage changes. CSP `connect-src 'none'` remains on the read-only news page; Preview CSP is unchanged.
- Last-source-fetch time is not publication time and does not make content current or true. A revision indicates changed publisher headline metadata, not a semantic correction verdict.

## Verification / runbook
`python scripts/news/test_collect.py` tests parser/date/URL/XML rules, dedup/revisions, scope, retention, partial/all-source failure, previous-snapshot fail-closed behavior, output escaping, manifest and DNS/redirect boundaries.
`ECHO_USE_BUNDLED_BROWSER=1 python scripts/news/browser_test.py` tests the served-origin read-only page with clearly synthetic fixtures, mobile reflow, search, source selector, age warning, keyboard and no-JS rendering.
`python scripts/news/collect.py --bootstrap --output verification/news-readiness` is the explicit live-source readiness probe; it must contain dated actual reports before the first release can be called ready. Never deploy unit-test fixtures as a fallback.
`python scripts/news/collect.py --output _site/news` is the production build path, with previous-deployment recovery.
Postdeployment verification compares four real HTTPS asset hashes to the **generated build artifact**, not a second fetch of mutable RSS. Data and manifest are retained with the run. Existing Room/Inspector/Feed and main browser tests still run.

To trigger manually: Actions -> Test and deploy Echo News -> Run workflow -> main. To pause, disable that schedule or remove the cron entry (ordinary main deploys also collect news). To add a source, verify its RSS/rights/URL policy, update the registry and tests through a reviewed PR; don't paste arbitrary URLs into the collector.

## SAT / VIOL / UNKNOWN
SAT only after actual final-head tests, live source response inspection, main deployment and published hash verification. Future cron execution is configured, not proven in advance. No new Event Engine/AI fact-checking/multi-user publishing status is implied. Human usability, full accessibility, broad media licensing, comprehensive coverage, production monitoring, evidence independence and semantic Event matching remain UNKNOWN.

Next: reviewed Source Report -> candidate Event linkage, preserving original reports and uncertainty. Never turn several articles into independent corroboration automatically.
