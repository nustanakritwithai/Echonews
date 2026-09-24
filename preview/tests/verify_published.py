"""Verify only the authorized Pages URL against the deployed static allowlist."""
import hashlib, json, os, pathlib, time, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = os.environ['PAGE_URL'].rstrip('/') + '/preview/'
FILES = ['index.html', 'styles.css', 'app.mjs', 'core.mjs', 'data.mjs', 'icon.svg', 'room-v2.mjs', 'room-v2.css']
results = []
for name in FILES:
    expected = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    record = {'file': name, 'url': BASE + name, 'expected_sha256': expected}
    for attempt in range(6):
        try:
            request = urllib.request.Request(BASE + name, headers={'Cache-Control': 'no-cache'})
            with urllib.request.urlopen(request, timeout=20) as response:
                actual = hashlib.sha256(response.read()).hexdigest()
                record.update(status=response.status, actual_sha256=actual, pass_check=actual == expected)
            if record['pass_check']:
                break
        except Exception as exc:
            record.update(pass_check=False, error=str(exc))
        if attempt < 5:
            time.sleep(5)
    results.append(record)
output = ROOT / 'results'
output.mkdir(exist_ok=True)
(output / 'published-site.json').write_text(json.dumps({'base_url': BASE, 'files': results}, indent=2))
for record in results:
    print(('SAT' if record['pass_check'] else 'VIOL') + ' ' + record['url'])
raise SystemExit(0 if all(r['pass_check'] for r in results) else 1)
