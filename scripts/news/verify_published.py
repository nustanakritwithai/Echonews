"""Verify generated news bytes against this build's artifact, not mutable upstream RSS."""
import hashlib,json,os
from pathlib import Path
import time
import urllib.request
ROOT=Path(__file__).resolve().parents[2]
base=os.environ['PAGE_URL'].rstrip('/')+'/news/'
if base!='https://nustanakritwithai.github.io/Echonews/news/':raise RuntimeError('unexpected publishing destination')
manifest=json.loads((ROOT/'verification/news-build/manifest.json').read_text())
if set(manifest)!={'index.html','news.css','news.js','data.json'}:raise RuntimeError('unexpected news manifest')
checks=[]
for filename,expected in manifest.items():
    row={'file':filename,'expected':expected}
    for attempt in range(6):
        try:
            with urllib.request.urlopen(urllib.request.Request(base+filename+'?check='+str(int(time.time())),headers={'Cache-Control':'no-cache'}),timeout=20) as response:
                row.update(status=response.status,actual=hashlib.sha256(response.read()).hexdigest())
                row['pass']=row['actual']==expected
            if row['pass']:break
        except Exception as error:row.update(pass_check=False,error=type(error).__name__)
        if attempt<5:time.sleep(5)
    checks.append(row)
path=ROOT/'verification/news-published.json'
path.write_text(json.dumps({'base':base,'files':checks},indent=2))
for row in checks:print(('SAT ' if row.get('pass') else 'VIOL ')+row['file'])
raise SystemExit(0 if all(r.get('pass') for r in checks) else 1)
