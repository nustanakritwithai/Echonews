"""Bounded daily RSS -> attributed source reports. Never facts, user voices or event matches.
No full article/image copying, LLM calls, API credentials or browser writes.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[2]
PREVIOUS_URL = 'https://nustanakritwithai.github.io/Echonews/news/data.json'
MODE = 'REAL_SOURCE_REPORTS'
MAX_BYTES = 2_000_000
MAX_RECORDS = 240
WINDOW_DAYS = 7
TITLE_LIMIT = 180
THAI_TOPICS = ('ไทย', 'รัฐบาล', 'ครม.', 'นายกฯ', 'รัฐสภา', 'พรรค', 'กทม.', 'กรุงเทพ', 'จังหวัด', 'สปส.', 'ประกันสังคม', 'ปภ.', 'กรม', 'ธปท.', 'ออมสิน', 'ส.อ.ท.', 'กสทช.', 'ปตท.', 'กกต.', 'ขนส่ง', 'เชียงใหม่', 'ภูเก็ต', 'นนทบุรี', 'นครราชสีมา', 'ชลบุรี', 'เงินบาท')
UA = 'EchoNewsDaily/1.0 (+https://github.com/nustanakritwithai/Echonews)'

class NewsError(Exception):
    pass

def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

def date(value: str) -> datetime:
    if not isinstance(value, str) or len(value) > 120:
        raise NewsError('INVALID_DATE')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        try:
            result = parsedate_to_datetime(value)
        except (ValueError, TypeError, OverflowError):
            raise NewsError('INVALID_DATE') from None
    if result.tzinfo is None or not 2000 <= result.year <= 2100:
        raise NewsError('AMBIGUOUS_DATE')
    return result.astimezone(timezone.utc)

class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.blocked = [], 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'): self.blocked += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style'): self.blocked = max(0, self.blocked - 1)
    def handle_data(self, value):
        if not self.blocked: self.parts.append(value)

def plain(value: str) -> str:
    p = PlainText()
    p.feed(value[:4000])
    return re.sub(r'\s+', ' ', re.sub(r'[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]', ' ', ''.join(p.parts))).strip()

def safe_url(value: str, hosts: list[str]) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or re.search(r'[\s\\\x00-\x1f\x7f]', value):
        raise NewsError('INVALID_URL')
    try:
        p = urllib.parse.urlsplit(value)
        if p.scheme != 'https' or p.hostname not in hosts or p.username or p.password or p.port not in (None, 443):
            raise NewsError('URL_NOT_ALLOWED')
    except ValueError:
        raise NewsError('INVALID_URL') from None
    # Never follow an item URL. It remains an attributed link for the reader.
    q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
         if not k.lower().startswith('utm_') and k.lower() not in ('fbclid', 'gclid')]
    return urllib.parse.urlunsplit(('https', p.hostname, p.path or '/', urllib.parse.urlencode(q), ''))

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts
    def redirect_request(self, request, fp, code, message, headers, newurl):
        # At most 3 same-allowlist HTTPS redirects. No arbitrary feed-provided URL.
        count = getattr(request, '_echo_redirects', 0)
        if count >= 3: raise NewsError('REDIRECT_LIMIT')
        url = safe_url(newurl, self.hosts)
        public_dns(urllib.parse.urlsplit(url).hostname)
        out = super().redirect_request(request, fp, code, message, headers, url)
        out._echo_redirects = count + 1
        return out

def public_dns(host):
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise NewsError('NONPUBLIC_ADDRESS')

def fetch(url: str, hosts: list[str]) -> bytes:
    url = safe_url(url, hosts)
    public_dns(urllib.parse.urlsplit(url).hostname)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        SafeRedirect(hosts), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept-Encoding': 'identity', 'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, application/json'})
    with opener.open(request, timeout=15) as response:
        safe_url(response.url, hosts)
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES: raise NewsError('RESPONSE_TOO_LARGE')
        if response.headers.get('Content-Encoding', 'identity') not in ('identity', ''):
            raise NewsError('UNSUPPORTED_CONTENT_ENCODING')
        return raw

def registry():
    config = json.loads((ROOT / 'scripts/news/sources.json').read_text())
    if config.get('schemaVersion') != 1 or not 1 <= len(config['feeds']) <= 8:
        raise NewsError('INVALID_REGISTRY')
    for source in config['feeds']:
        safe_url(source['feedUrl'], source['hosts'])
        safe_url(source['policyUrl'], source['hosts'])
    return config['feeds']

def tag(element):
    return element.tag.rsplit('}', 1)[-1].lower()

def child_text(item, name):
    return next((''.join(e.itertext()) for e in item if tag(e) == name), '')

def parse_feed(raw: bytes, source: dict, now: datetime) -> tuple[list, dict]:
    if len(raw) > MAX_BYTES: raise NewsError('RESPONSE_TOO_LARGE')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise NewsError('UTF8_REQUIRED') from None
    if re.search(r'<!\s*(?:doctype|entity)', text, re.I): raise NewsError('XML_DECLARATION_DENIED')
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise NewsError('INVALID_FEED_XML') from None
    if tag(root) not in ('rss', 'rdf', 'feed'): raise NewsError('NOT_A_FEED')
    entries = [e for e in root.iter() if tag(e) in ('item', 'entry')]
    if len(entries) > 1000: raise NewsError('TOO_MANY_ENTRIES')
    stats = dict(seen=len(entries), accepted=0, skippedDate=0, skippedUrl=0, skippedScope=0)
    result = []
    cutoff = now - timedelta(days=WINDOW_DAYS)
    digest = hashlib.sha256(raw).hexdigest()
    for item in entries:
        categories = [plain(e.text or e.get('term', '')) for e in item if tag(e) == 'category']
        if any(word in ' '.join(categories).lower() for word in source.get('excludeCategories', [])):
            stats['skippedScope'] += 1; continue
        headline = plain(child_text(item, 'title'))
        if not headline: continue
        if source.get('requireThaiTopic') and not any(word in headline + ' ' + ' '.join(categories) for word in THAI_TOPICS):
            stats['skippedScope'] += 1; continue
        link = child_text(item, 'link').strip()
        if tag(item) == 'entry':
            link = next((e.get('href', '') for e in item if tag(e) == 'link' and e.get('rel', 'alternate') == 'alternate'), '')
        try:
            url = safe_url(link, source['hosts'])
            if not re.match(source['articlePathPattern'], urllib.parse.urlsplit(url).path):
                raise NewsError('ARTICLE_PATH_NOT_ALLOWED')
        except NewsError:
            stats['skippedUrl'] += 1; continue
        try:
            published = date(child_text(item, 'pubdate') or child_text(item, 'published') or child_text(item, 'date'))
            if published > now or published < cutoff: raise NewsError('OUTSIDE_NEWS_WINDOW')
        except NewsError:
            stats['skippedDate'] += 1; continue
        record_id = hashlib.sha256((source['publisherId'] + '\n' + url).encode()).hexdigest()[:32]
        result.append(dict(id=record_id, publisherId=source['publisherId'], title=headline[:TITLE_LIMIT],
            titleTruncated=len(headline) > TITLE_LIMIT, url=url, publishedAt=iso(published),
            firstSeenAt=iso(now), lastSeenAt=iso(now), sourceFeedIds=[source['id']],
            evidenceState='UNKNOWN', eventMatchState='UNASSIGNED',
            revisions=[dict(observedAt=iso(now), title=headline[:TITLE_LIMIT], publishedAt=iso(published), feedSha256=digest)]))
    stats['accepted'] = len(result)
    return result, stats

def empty_snapshot():
    return dict(schemaVersion=1, mode=MODE, generatedAt=None, lastSuccessfulFetchAt=None,
                status='NOT_FETCHED', records=[], sources=[])

def validate_snapshot(data, feeds):
    if not isinstance(data, dict) or data.get('schemaVersion') != 1 or data.get('mode') != MODE:
        raise NewsError('INVALID_SNAPSHOT')
    records = data.get('records')
    if not isinstance(records, list) or len(records) > MAX_RECORDS: raise NewsError('INVALID_SNAPSHOT_RECORDS')
    publishers = {f['publisherId']: f for f in feeds}
    known_feeds = {f['id'] for f in feeds}
    seen = set()
    for r in records:
        if not isinstance(r, dict) or r.get('publisherId') not in publishers: raise NewsError('UNKNOWN_PUBLISHER')
        src = publishers[r['publisherId']]
        url = safe_url(r['url'], src['hosts'])
        if not re.match(src['articlePathPattern'], urllib.parse.urlsplit(url).path): raise NewsError('INVALID_ARTICLE_PATH')
        expected = hashlib.sha256((src['publisherId']+'\n'+url).encode()).hexdigest()[:32]
        if r['id'] != expected or r['id'] in seen: raise NewsError('INVALID_RECORD_ID')
        seen.add(r['id'])
        if r.get('evidenceState') != 'UNKNOWN' or r.get('eventMatchState') != 'UNASSIGNED': raise NewsError('UNSUPPORTED_TRUTH_CLAIM')
        if not isinstance(r['title'], str) or not 1 <= len(r['title']) <= TITLE_LIMIT: raise NewsError('INVALID_TITLE')
        if not set(r['sourceFeedIds']) <= known_feeds: raise NewsError('UNKNOWN_FEED')
        for key in ('publishedAt', 'firstSeenAt', 'lastSeenAt'): date(r[key])
        if not isinstance(r['revisions'], list) or not r['revisions']: raise NewsError('INVALID_REVISIONS')
        for rev in r['revisions']:
            if not isinstance(rev['title'], str) or not 1 <= len(rev['title']) <= TITLE_LIMIT: raise NewsError('INVALID_REVISION')
            date(rev['observedAt']); date(rev['publishedAt'])
            if not re.fullmatch('[a-f0-9]{64}', rev['feedSha256']): raise NewsError('INVALID_PROVENANCE_HASH')
    for key in ('generatedAt', 'lastSuccessfulFetchAt'):
        if data.get(key): date(data[key])
    return data

def collect(feeds, previous, now, fetcher=fetch):
    validate_snapshot(previous, feeds)
    if previous.get('generatedAt') and date(previous['generatedAt']) > now: raise NewsError('FUTURE_SNAPSHOT')
    cutoff = now - timedelta(days=WINDOW_DAYS)
    records = {r['id']: copy.deepcopy(r) for r in previous['records'] if cutoff <= date(r['publishedAt']) <= now}
    health = []
    succeeded = 0
    for source in feeds:
        try:
            raw = fetcher(source['feedUrl'], source['hosts'])
            rows, stats = parse_feed(raw, source, now)
            succeeded += 1
            health.append(dict(id=source['id'], publisherId=source['publisherId'], feedUrl=source['feedUrl'], status='OK', checkedAt=iso(now), **stats))
            for r in rows:
                old = records.get(r['id'])
                if old:
                    r['firstSeenAt'] = old['firstSeenAt']
                    r['sourceFeedIds'] = sorted(set(old['sourceFeedIds']) | set(r['sourceFeedIds']))
                    revisions = old['revisions']
                    if (old['title'], old['publishedAt']) != (r['title'], r['publishedAt']):
                        revisions = revisions + r['revisions']
                    r['revisions'] = revisions
                records[r['id']] = r
        except Exception as error:
            # No raw response, secrets or exception details enter the public snapshot.
            health.append(dict(id=source['id'], publisherId=source['publisherId'], feedUrl=source['feedUrl'], status='UNAVAILABLE', checkedAt=iso(now),
                               errorCode=error.args[0] if type(error) is NewsError else 'FETCH_OR_PARSE_FAILED'))
    if not records and succeeded == 0:
        raise NewsError('NO_VALID_SOURCE_OR_PREVIOUS_NEWS')
    status = 'OK' if succeeded == len(feeds) else ('PARTIAL' if succeeded else 'STALE')
    output = dict(schemaVersion=1, mode=MODE, generatedAt=iso(now),
        lastSuccessfulFetchAt=iso(now) if succeeded else previous.get('lastSuccessfulFetchAt'),
        status=status, records=sorted(records.values(), key=lambda r: (r['publishedAt'], r['id']), reverse=True)[:MAX_RECORDS],
        sources=health)
    return validate_snapshot(output, feeds)

def previous_snapshot(feeds, fetcher=fetch):
    try:
        # Cache-busting read of this exact deployment path; never an external URL from RSS.
        raw = fetcher(PREVIOUS_URL+'?echo_snapshot='+str(int(time.time())), ['nustanakritwithai.github.io'])
    except urllib.error.HTTPError as error:
        if error.code == 404: return empty_snapshot()
        raise NewsError('PREVIOUS_SNAPSHOT_UNAVAILABLE') from None
    except Exception:
        raise NewsError('PREVIOUS_SNAPSHOT_UNAVAILABLE') from None
    try:
        return validate_snapshot(json.loads(raw), feeds)
    except Exception:
        raise NewsError('PREVIOUS_SNAPSHOT_INVALID') from None

def thai_time(value):
    return date(value).astimezone(ZoneInfo('Asia/Bangkok')).strftime('%d/%m/%Y %H:%M') if value else 'ยังไม่มีการดึงสำเร็จ'

def render(snapshot, feeds):
    validate_snapshot(snapshot, feeds)
    esc = lambda s: html.escape(str(s), quote=True)
    names = {f['publisherId']: f for f in feeds}
    categories = {f['id']: f['label'] for f in feeds}
    cards = []
    for r in snapshot['records']:
        publisher = names[r['publisherId']]
        changes = ''
        if len(r['revisions']) > 1:
            changes = '<details class="history"><summary>พาดหัวที่ระบบเคยพบ ('+str(len(r['revisions']))+' รุ่น)</summary>'+''.join(
                '<p><time>'+esc(thai_time(x['observedAt']))+'</time> · '+esc(x['title'])+'</p>' for x in reversed(r['revisions']))+'</details>'
        cards.append(f'''<article class="report" data-publisher="{esc(r['publisherId'])}" data-title="{esc(r['title'])}" data-published="{esc(r['publishedAt'])}">
<div class="report-top"><span class="source">{esc(publisher['publisherName'])}</span><span class="kind">รายงานจากต้นทาง</span></div>
<h2><a href="{esc(r['url'])}" target="_blank" rel="noopener noreferrer">{esc(r['title'])}{'…' if r['titleTruncated'] else ''}</a></h2>
<p class="published">ต้นทางเผยแพร่ <time datetime="{esc(r['publishedAt'])}">{esc(thai_time(r['publishedAt']))}</time> น. (ไทย)</p>
<div class="report-bottom"><span class="unknown">ยังไม่ได้ตรวจยืนยัน · UNKNOWN</span><a href="{esc(r['url'])}" target="_blank" rel="noopener noreferrer">อ่านที่ต้นทาง ↗</a></div>
<details class="provenance"><summary>ดูที่มาและเวลาที่นำเข้า</summary><p>หมวดจากฟีด: {esc(' / '.join(categories[f] for f in r['sourceFeedIds']))}</p><p>พบครั้งแรก {esc(thai_time(r['firstSeenAt']))} · พบล่าสุด {esc(thai_time(r['lastSeenAt']))} น.</p><p>ยังไม่จัดเข้าห้องเหตุการณ์ · ไม่ถือว่าหลายรายงานเป็นหลายหลักฐานอิสระ</p><code>Report ID: {esc(r['id'])}</code></details>{changes}</article>''')
    source_options = ''.join('<option value="'+esc(k)+'">'+esc(v['publisherName'])+'</option>' for k,v in names.items())
    health_rows = ''.join('<li><strong>'+esc(next(f['label'] for f in feeds if f['id']==h['id']))+'</strong> — '+('ดึงฟีดสำเร็จ · รับ '+str(h['accepted'])+' รายการในช่วง 7 วัน' if h['status']=='OK' else 'ดึงไม่สำเร็จ · ไม่เติมข่าวสมมติแทน')+'</li>' for h in snapshot['sources'])
    return f'''<!doctype html><html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"><meta name="theme-color" content="#101510"><title>ข่าวไทยจากต้นทาง · Echo News</title><link rel="stylesheet" href="./news.css"><script src="./news.js" defer></script></head>
<body><a class="skip" href="#reports">ข้ามไปข่าว</a><header class="masthead"><a class="brand" href="../">echo<span>.</span></a><nav aria-label="เมนู"><a href="../preview/">ห้องทดลอง</a><a href="#sources">แหล่งข่าว</a></nav></header><main>
<section class="intro"><p class="eyebrow">THAILAND / SOURCE REPORTS</p><h1>ข่าวไทย<br><span>จากต้นทาง</span></h1><p class="lead">ติดตามรายงานล่าสุดที่ระบบดึงได้ ไม่ใช่ข้อเท็จจริงที่ Echo ตรวจยืนยันแล้ว</p><div class="schedule"><strong>อัปเดตทุกวัน 08:15 น.</strong><span>เวลาไทย · GitHub Actions อาจเริ่มล่าช้า</span></div></section>
<section id="health" class="health" data-last-success="{esc(snapshot['lastSuccessfulFetchAt'] or '')}" data-status="{esc(snapshot['status'])}"><strong id="health-label">{ {'OK':'ดึงฟีดรอบล่าสุดสำเร็จ','PARTIAL':'บางฟีดยังดึงไม่ได้','STALE':'ดึงรอบนี้ไม่สำเร็จ · แสดงข้อมูลเดิม','NOT_FETCHED':'ยังไม่เริ่มดึงข้อมูล'}.get(snapshot['status'], 'ตรวจสถานะการดึงข่าว') }</strong><p>ดึงสำเร็จล่าสุด <time>{esc(thai_time(snapshot['lastSuccessfulFetchAt']))}</time> น.</p><p>สร้างชุดข้อมูล {esc(thai_time(snapshot['generatedAt']))} น. · เวลาที่ดึง ≠ เวลาที่ข่าวเกิดขึ้น</p></section>
<div class="controls"><label for="news-search">ค้นพาดหัว<input id="news-search" type="search" placeholder="เช่น ฝน คมนาคม เศรษฐกิจ" maxlength="100"></label><label for="news-source">แหล่งข่าว<select id="news-source"><option value="all">ทุกแหล่ง</option>{source_options}</select></label></div><p id="result-count" role="status" aria-live="polite">{len(cards)} รายงาน · จากฟีดที่เลือก ช่วง 7 วันที่ผ่านมา</p>
<section id="reports" aria-label="รายงานจากต้นทาง">{''.join(cards) or '<p class="empty">ยังไม่มีรายงานที่ระบุเวลาและผ่านเงื่อนไขช่วง 7 วัน ไม่ใช้ข้อมูลจำลองแทนข่าวจริง</p>'}</section><p id="no-results" class="empty" hidden>ไม่พบพาดหัวที่ตรงกับคำค้น</p>
<section id="sources" class="sources"><p class="eyebrow">TRANSPARENCY</p><h2>รู้ที่มา รู้ข้อจำกัด</h2><ul>{health_rows}</ul><p>เลือกเฉพาะฟีดที่ระบุไว้ในทะเบียนแหล่งข่าว กรองหัวข้อเกี่ยวกับไทยด้วยคำสำคัญซึ่งอาจตกหล่น ดึงเฉพาะรายการที่ยังอยู่ใน RSS ขณะรัน ไม่ใช่ข่าวครบทั้งวันหรือทุกข่าวในประเทศไทย แสดงพาดหัวไม่เกิน 180 ตัวอักษรและลิงก์กลับ ไม่คัดลอกเนื้อหาข่าวเต็มหรือรูปภาพ</p><p>จำนวนรายงานไม่ใช่จำนวนข้อเท็จจริงหรือแหล่งอิสระ ยังไม่รวมรายงานเป็นเหตุการณ์เดียวโดยอัตโนมัติ ข้อมูลจำลองและโพสต์ในเครื่องแยกอยู่ในห้องทดลอง</p><p>ข่าวรายวันไม่ใช่บริการแจ้งเตือนฉุกเฉิน ข้อมูลใหม่อาจยังไม่อยู่ในฟีด หากอัปเดตขาดช่วงให้ดูวันที่เผยแพร่จากต้นทาง</p>{''.join('<p><a href="'+esc(f['policyUrl'])+'" target="_blank" rel="noopener noreferrer">เงื่อนไข / RSS ของ '+esc(f['publisherName'])+' ↗</a></p>' for f in names.values())}<a href="./data.json">ดูข้อมูลและที่มาแบบ JSON</a></section></main><footer>Echo News Center · ข่าวจริงจากต้นทาง / ไม่ใช่ผลตรวจข้อเท็จจริง<br><a href="../preview/">กลับห้องทดลอง</a></footer></body></html>'''

def write_output(snapshot, feeds, output):
    output.mkdir(parents=True, exist_ok=True)
    (output/'data.json').write_text(json.dumps(snapshot, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    (output/'index.html').write_text(render(snapshot, feeds), encoding='utf-8')
    for name in ('news.css', 'news.js'):
        (output/name).write_bytes((ROOT/'news'/name).read_bytes())
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir()) if p.name in ('index.html','data.json','news.css','news.js')}
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bootstrap', action='store_true', help='Explicit probe/first-install only; ignore prior snapshot')
    args = parser.parse_args()
    feeds = registry()
    previous = empty_snapshot() if args.bootstrap else previous_snapshot(feeds)
    snapshot = collect(feeds, previous, datetime.now(timezone.utc))
    write_output(snapshot, feeds, args.output)
    print(json.dumps(dict(status=snapshot['status'], records=len(snapshot['records']), generatedAt=snapshot['generatedAt'], sources=snapshot['sources']), ensure_ascii=False))
    if not snapshot['records']: raise NewsError('NO_RECENT_REPORTS_READY')

if __name__ == '__main__':
    main()
