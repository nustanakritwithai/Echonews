# Echo Voice Room — alternative preview

This alternative, synthetic UI lives at /Echonews/preview/. The root application and database work are intentionally preserved after a concurrent update to main.

All initial people, places, reports, evidence and claim labels are fictional fixtures. This is not emergency information. Local posts are not sent to anyone. No login, API, automatic event matching or AI verification is connected. Selection and voice typing are manual. Added voices do not change prepared evidence labels.

Storage: echo.preview.v1, distinct from the root application's echo-news-preview-v1. Both share an origin; neither is secure storage. Do not enter secrets or sensitive personal information. Room-excluded drafts do not enter room views/counts/search; owners may withdraw or delete local posts.

Tests: node --test preview/tests/core.test.mjs. CI uses Python Playwright 1.56.0 and ECHO_USE_BUNDLED_BROWSER=1 python preview/tests/browser_test.py. The root .github/workflows/pages.yml tests both designs and stages only the explicit public asset allowlist. It never deploys PRs.

Local verification: 32 Node tests and 21 offline DOM assertions passed. Offline tests substitute Storage and scripts and do not validate HTTP/modules/CSP. Actual HTTP suite is verified separately by CI. Live deployment requires a successful Pages job plus published-asset checks.

Research-gate labels inside the frozen About view describe the preview's unconnected reference scope, not live repository CI. The repository's separate PostgreSQL gate reported success at Actions run 35863662395. This page still does not connect to that database or enable real-user reporting.
