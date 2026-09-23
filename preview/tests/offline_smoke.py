"""Offline DOM smoke test, NOT HTTP/module/CSP validation.
Explicitly substitutes in-memory Storage on about:blank because local HTTP is unavailable.
The independent browser_test.py remains the real HTTP integration suite for CI.
"""
import json, pathlib, re, shutil
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[1]
html=(ROOT/'index.html').read_text()
html=re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>','',html)
html=re.sub(r'<link[^>]*>','',html)
html=re.sub(r'<script[^>]*>.*?</script>','',html,flags=re.S)
bundle='\n'.join(re.sub(r'^import .*?;\n','', (ROOT/name).read_text(), flags=re.M).replace('export ', '') for name in ['core.mjs','data.mjs','app.mjs'])
bundle=bundle.replace("const app=document.querySelector", "const esc = escapeHTML;\nconst app=document.querySelector")
bundle=bundle.replace('<img src="./icon.svg" alt="">','')
checks=[]
def check(name,cond):
    checks.append({'name':name,'pass':bool(cond)})
    if not cond:raise AssertionError(name)
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=shutil.which('chromium'),headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':390,'height':844})
    errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
    page.set_content(html)
    page.add_style_tag(content=(ROOT/'styles.css').read_text())
    page.evaluate("""() => {
       const store=new Map();
       Object.defineProperty(window,'localStorage',{value:{getItem:k=>store.has(k)?store.get(k):null,setItem:(k,v)=>store.set(k,String(v)),removeItem:k=>store.delete(k)}});
       if(!crypto.randomUUID)crypto.randomUUID=()=> 'offline-'+Math.random().toString(36).slice(2);
    }""")
    page.add_script_tag(content='(()=>{'+bundle+'})();')
    check('3 event cards in offline DOM',page.locator('.feed .card').count()==3)
    for w in [320,360,390,700,1280,1440]:
        page.set_viewport_size({'width':w,'height':900})
        check(f'no horizontal overflow at {w}',page.evaluate('document.documentElement.scrollWidth<=innerWidth'))
    page.set_viewport_size({'width':390,'height':844})
    page.screenshot(path=str(ROOT/'results/mobile-feed.png'),full_page=True)
    page.evaluate("location.hash='/room/canal-demo'");page.wait_for_timeout(150)
    check('6 original voices in room',page.locator('#room-body .voicecard').count()==6)
    page.screenshot(path=str(ROOT/'results/mobile-room.png'),full_page=True)
    page.locator('[data-action=claim][data-id=c1]').click()
    check('claim evidence drilldown opens',page.locator('#modal .evidencecard').count()==2)
    page.locator('#modal [data-action=original]').first.click()
    check('source voice accessible','ต้นทาง v1' in page.locator('#modal').inner_text())
    page.keyboard.press('Escape')
    page.locator('[data-action=tab][data-value=evidence]').click()
    check('3 evidence refs shown',page.locator('#room-body .evidencecard').count()==3)
    page.locator('[data-action=tab][data-value=timeline]').click()
    check('4 timeline entries shown',page.locator('.moment').count()==4)
    page.locator('.bottomnav [data-action=compose]').click()
    check('draft exclusion default',not page.locator('#include-room').is_checked())
    page.locator('#voice-text').fill('OFFLINE_PRIVATE_DRAFT')
    page.locator('#voice-form button[type=submit]').click();page.wait_for_timeout(120)
    check('draft original retained',page.locator('#main .voicecard').count()==1)
    page.evaluate("location.hash='/room/canal-demo'");page.wait_for_timeout(100)
    check('draft not in room or count',page.locator('#room-body .voicecard').count()==6 and 'OFFLINE_PRIVATE_DRAFT' not in page.locator('#main').inner_text())
    page.locator('.bottomnav [data-action=compose]').click()
    page.locator('#voice-text').fill('<img src=x onerror="window.PWNED=true">')
    page.locator('#include-room').check()
    page.locator('#voice-form button[type=submit]').click();page.wait_for_timeout(100)
    check('explicit opt-in adds a voice',page.locator('#room-body .voicecard').count()==7)
    check('HTML rendered as text, not image',page.locator('#room-body .voicecontent img').count()==0 and not page.evaluate('Boolean(window.PWNED)'))
    page.evaluate("location.hash='/me'");page.wait_for_timeout(100)
    page.locator('[data-action=visibility]').first.click()
    page.evaluate("location.hash='/room/canal-demo'");page.wait_for_timeout(100)
    check('withdrawal removes room contribution',page.locator('#room-body .voicecard').count()==6)
    page.locator('.roomtools [data-action=follow]').click()
    page.evaluate("location.hash='/following'");page.wait_for_timeout(100)
    check('follow filter works',page.locator('.feed .card').count()==1)
    page.evaluate("location.hash='/'");page.wait_for_timeout(100)
    page.locator('#search').fill('OFFLINE_PRIVATE_DRAFT')
    check('draft excluded from search',page.locator('.feed .card').count()==0)
    page.locator('#search').fill('')
    page.set_viewport_size({'width':1440,'height':1080})
    page.screenshot(path=str(ROOT/'results/desktop-feed.png'),full_page=True)
    check('no JavaScript runtime errors in offline DOM',errors==[])
    browser.close()
(ROOT/'results/offline-smoke.json').write_text(json.dumps({'mode':'OFFLINE_DOM_WITH_TEST_STORAGE_NOT_HTTP','checks':checks,'http_module_csp':'UNKNOWN_LOCALLY'},indent=2))
print(f'{len(checks)} offline DOM assertions passed; HTTP/CSP/native storage integration remains untested locally.')
