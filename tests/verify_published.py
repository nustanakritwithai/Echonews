"""Read-only post-deployment check: HTTP responses and exact public asset digests.
No tokens, user data, or backend requests are sent to the published site.
"""
import hashlib
import json
import os
import time
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get('PAGE_URL', 'https://nustanakritwithai.github.io/Echonews/')
if BASE != 'https://nustanakritwithai.github.io/Echonews/':
    raise SystemExit('Refusing to check an unexpected deployment host or path')
FILES = ('index.html', 'style.css', 'app.js', 'core.js', 'data.js', 'favicon.svg')
results = []
for name in FILES:
    expected = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    for attempt in range(6):
        try:
            req = Request(BASE + name, headers={'User-Agent': 'EchoNews-Deployment-Check/0.1', 'Cache-Control': 'no-cache'})
            with urlopen(req, timeout=20) as response:
                body = response.read(2_000_000)
                actual = hashlib.sha256(body).hexdigest()
                if response.status != 200 or actual != expected:
                    raise ValueError(f'{name}: HTTP {response.status}, content differs from tested commit')
                results.append({'asset': name, 'http_status': response.status, 'sha256': actual, 'matches_tested_source': True})
                print(f'PASS | published {name} | HTTP 200 | exact source match', flush=True)
                break
        except Exception as exc:
            if attempt == 5:
                raise
            print(f'Retry {attempt + 1} | {name} | {type(exc).__name__}', flush=True)
            time.sleep(5)
report = {'url': BASE, 'commit': os.environ.get('GITHUB_SHA'), 'mode': 'real HTTPS published assets; not a live browser test', 'assets': results}
(ROOT / 'verification').mkdir(exist_ok=True)
(ROOT / 'verification/published-site.json').write_text(json.dumps(report, indent=2))
print(json.dumps({'public_assets_passed': len(results), 'url': BASE}))
