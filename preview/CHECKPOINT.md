# WEB-PREVIEW-01 — additive Echo Voice Room

Scope: publish an alternative mobile-first design under /preview/ without replacing the root application that arrived concurrently in main at fdc19a68f2f9c0adbf8ef6358449b1a955d86fc1.

Original PR #2 was closed unmerged to preserve that work. All root app.js/core.js/data.js/style.css/index.html, database files, original tests, and PostgreSQL workflow remain unchanged. The Pages workflow adds test and staging of the alternative and a PR deployment guard.

Implemented: event feed, Reality/Society split, original voices, evidence references, fictional timeline, local drafts/explicit room inclusion/withdraw/delete, follows and search. No real news, login, backend or AI assessment.

Local SAT: 32 Node tests; 21 offline DOM assertions. HTTP browser tests and public asset availability must be verified in Actions before claiming live deployment. Results must distinguish backend CI from frontend readiness.

Next: verify the integrated preview CI and published assets. Resume authenticated API/visibility work only after reviewing the separate PostgreSQL runtime evidence; this UI does not bypass backend safety gates.
