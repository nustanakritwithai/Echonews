"""Offline Chromium checks. Requests are fulfilled from disk at a synthetic HTTPS origin.
No news source, deployed website, or network backend is contacted by this test.
Run: python tests/browser_smoke.py (requires Playwright and Chromium).
"""
import json, mimetypes, os, shutil
from pathlib import Path
from urllib.parse import urlparse, unquote
from playwright.sync_api import sync_playwright, expect
ROOT=Path(__file__).resolve().parents[1]
BASE='https://echonews-preview.example/Echonews/'
RESULTS=[]
(ROOT/'verification').mkdir(exist_ok=True)
def record(name): RESULTS.append({'name':name,'status':'PASS'})
def fulfill(route):
    u=urlparse(route.request.url)
    if u.hostname!='echonews-preview.example' or not u.path.startswith('/Echonews/'):
        route.abort();return
    rel=unquote(u.path[len('/Echonews/'):]) or 'index.html'
    path=(ROOT/rel).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        route.fulfill(status=404,body='Not found');return
    route.fulfill(status=200,body=path.read_bytes(),content_type=mimetypes.guess_type(str(path))[0] or 'application/octet-stream')
with sync_playwright() as p:
    exe=os.environ.get('CHROMIUM_EXECUTABLE') or shutil.which('chromium')
    browser=p.chromium.launch(headless=True,executable_path=exe,args=['--no-sandbox'])
    context=browser.new_context(viewport={'width':1440,'height':1000},device_scale_factor=1)
    context.route('**/*',fulfill)
    page=context.new_page();errors=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    page.goto(BASE,wait_until='networkidle')
    expect(page.locator('.card')).to_have_count(4);record('home has exactly four event cards')
    expect(page.locator('.demo-strip')).to_contain_text('ไม่ใช่ข่าวปัจจุบัน');record('demo disclosure is visible')
    page.screenshot(path=str(ROOT/'verification/desktop-home.png'),full_page=True)
    page.locator('#search').fill('ผู้ช่วย AI');expect(page.locator('.card')).to_have_count(1);record('search filters events')
    page.locator('#search').fill('');page.locator('#main [data-action="topic"][data-value="สิ่งแวดล้อม"]').click()
    expect(page.locator('.card')).to_have_count(1);record('category filter works')
    page.locator('#main [data-action="topic"][data-value="ทั้งหมด"]').click()
    page.locator('.card[data-room="canal-demo"] [data-action="follow"]').click()
    page.goto(BASE+'#/following');expect(page.locator('.card')).to_have_count(1);record('followed feed contains selected room')
    page.reload(wait_until='networkidle');expect(page.locator('.card')).to_have_count(1);record('follow survives reload')
    page.goto(BASE+'#/room/canal-demo');expect(page.locator('.room-header h1')).to_contain_text('คลองเหนือ')
    expect(page.locator('.const-center b')).to_have_text('6');record('deep linked room loads')
    page.locator('[data-action="claim"][data-id="road-closed"]').click()
    expect(page.locator('dialog')).to_be_visible();expect(page.locator('dialog')).to_contain_text('คัดค้าน · 1')
    record('claim exposes both supporting and opposing refs')
    page.locator('dialog [data-action="original"][data-id="v04"]').click()
    expect(page.locator('dialog .voice-text')).to_contain_text('ข้อมูลที่ฉันเห็น');record('claim drills down to original voice')
    page.keyboard.press('Escape');expect(page.locator('dialog')).not_to_be_visible();record('dialog keyboard escape works')
    page.locator('.room-header [data-action="compose"]').click()
    page.locator('#voice-text').fill('ข้อความทดสอบสาธารณะ <img src=x onerror=alert(1)>')
    page.locator('#voice-kind').select_option('observation')
    page.locator('#compose-form button[type="submit"]').click()
    expect(page.locator('dialog')).not_to_be_visible()
    expect(page.locator('#room-body .voice-text').filter(has_text='ข้อความทดสอบสาธารณะ')).to_have_count(1)
    record('composer adds a linked local voice')
    expect(page.locator('.pending-strip')).to_contain_text('1 เสียงใหม่รอตรวจ');record('new post is marked pending, not verified')
    expect(page.locator('.reality .claim.disputed')).to_have_count(1);record('new voice does not change evidence status')
    assert page.locator('.voice-text img').count()==0;record('user HTML is inert text')
    page.locator('.room-header [data-action="compose"]').click()
    page.locator('#voice-text').fill('ความลับเฉพาะเครื่อง-needle')
    page.locator('[name="shared"]').uncheck()
    page.locator('#compose-form button[type="submit"]').click()
    expect(page.locator('.voice-text').filter(has_text='ความลับเฉพาะเครื่อง-needle')).to_have_count(1)
    record('unlinked voice remains in owner feed')
    page.goto(BASE+'#/room/canal-demo')
    expect(page.locator('#main')).not_to_contain_text('ความลับเฉพาะเครื่อง-needle')
    expect(page.locator('.voice-count')).to_have_text('7 VOICES');record('unlinked voice does not leak to room or count')
    page.goto(BASE+'#/');page.locator('#search').fill('ความลับเฉพาะเครื่อง-needle')
    expect(page.locator('.card')).to_have_count(0);record('unlinked voice does not leak into event search')
    page.locator('#search').fill('');page.goto(BASE+'#/mine')
    page.locator('.voice-card').filter(has_text='ความลับเฉพาะเครื่อง-needle').locator('[data-action="delete-ask"]').click()
    page.locator('[data-action="delete-confirm"]').click()
    expect(page.locator('#main')).not_to_contain_text('ความลับเฉพาะเครื่อง-needle');record('withdraw removes local original')
    page.goto(BASE+'#/room/canal-demo');page.locator('.room-header [data-action="compose"]').click()
    page.locator('#voice-room').select_option('__new__');page.locator('#new-title').fill('ห้องใหม่เพื่อทดสอบ')
    page.locator('#voice-text').fill('ทดลองสร้างห้องจากโพสต์ต้นฉบับ')
    page.locator('#compose-form button[type="submit"]').click()
    expect(page.locator('.room-header h1')).to_have_text('ห้องใหม่เพื่อทดสอบ')
    expect(page.locator('.reality')).to_contain_text('ยังไม่มีข้อกล่าวอ้างที่ผ่านการประเมิน');record('new local room starts without fabricated claims')
    page.reload(wait_until='networkidle');expect(page.locator('.room-header h1')).to_have_text('ห้องใหม่เพื่อทดสอบ');record('new room survives reload and hash route')
    page.goto(BASE+'#/about');page.locator('#main [data-action="reset-ask"]').click()
    page.locator('[data-action="reset-confirm"]').click();record('reset requires explicit confirmation')
    page.goto(BASE+'#/mine');expect(page.locator('#main')).to_contain_text('0 โพสต์');record('reset clears local posts')
    page.goto(BASE+'#/missing-room-route');expect(page.locator('#main')).to_contain_text('ไม่พบหน้านี้');record('unknown route fails clearly')
    for width in [360,390,768,1440]:
        page.set_viewport_size({'width':width,'height':844})
        page.goto(BASE+'#/')
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'),f'home overflow {width}'
        page.goto(BASE+'#/room/canal-demo')
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'),f'room overflow {width}'
        record(f'home and room have no horizontal overflow at {width}px')
    page.set_viewport_size({'width':390,'height':844});page.goto(BASE+'#/')
    expect(page.locator('.bottom-nav')).to_be_visible();record('mobile bottom navigation is visible')
    page.screenshot(path=str(ROOT/'verification/mobile-home.png'),full_page=True)
    page.locator('[data-action="search"]').click();expect(page.locator('#search')).to_be_visible();record('mobile search opens')
    page.goto(BASE+'#/room/canal-demo');page.screenshot(path=str(ROOT/'verification/mobile-room.png'),full_page=True)
    page.locator('.cluster-node.k-question').click()
    expect(page.locator('#room-body .voice-card')).to_have_count(1);record('orbit node opens filtered original voices')
    assert errors==[],errors;record('no JavaScript page errors during smoke tests')
    browser.close()
(ROOT/'verification/browser-tests.json').write_text(json.dumps({'mode':'offline HTTPS request interception; not deployed-browser verification','count':len(RESULTS),'results':RESULTS,'page_errors':errors},ensure_ascii=False,indent=2))
print(json.dumps({'passed':len(RESULTS),'page_errors':errors},ensure_ascii=False))
