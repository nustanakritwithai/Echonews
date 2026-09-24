"""Native served-origin /Echonews/news/ tests use named synthetic fixtures only."""
import functools
import http.server
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect as n
from test_collect import NOW, SOURCE, rss
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[2]
RESULTS=ROOT/'verification/news-browser'
RESULTS.mkdir(parents=True,exist_ok=True)
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self,*args):pass

class NewsBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.host=Path(cls.temp.name)
        cls.snapshot=n.collect([SOURCE],n.empty_snapshot(),NOW,lambda *a: rss('ไทย กรมอุตุฯ — พาดหัวทดสอบเท่านั้น'))
        for i,title in enumerate(('ประเทศไทย ขนส่ง — รายงานทดสอบ','ไทย เศรษฐกิจ — รายงานทดสอบ'),start=2):
            item=n.parse_feed(rss(title,link=f'https://example.com/2026/{i}'),SOURCE,NOW)[0][0]
            cls.snapshot['records'].append(item)
        n.write_output(cls.snapshot,[SOURCE],cls.host/'Echonews/news')
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=cls.host))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url=f'http://127.0.0.1:{cls.server.server_port}/Echonews/news/'
        cls.pw=sync_playwright().start()
        executable=None if os.environ.get('ECHO_USE_BUNDLED_BROWSER') else shutil.which('chromium')
        cls.browser=cls.pw.chromium.launch(headless=True,**({'executable_path':executable} if executable else {}),args=['--no-sandbox'])
    @classmethod
    def tearDownClass(cls):
        cls.browser.close();cls.pw.stop();cls.server.shutdown();cls.temp.cleanup()
    def setUp(self):
        self.context=self.browser.new_context(viewport={'width':360,'height':800})
        self.page=self.context.new_page();self.errors=[];self.requests=[]
        self.page.on('pageerror',lambda error:self.errors.append(str(error)))
        self.page.on('request',lambda request:self.requests.append((request.url,request.method)))
        self.page.goto(self.url);self.page.wait_for_selector('.report')
    def tearDown(self):
        self.context.close();self.assertEqual(self.errors,[])
    def test_01_attributed_reports_not_claims(self):
        self.assertEqual(self.page.locator('.report').count(),3)
        expect(self.page.locator('h1')).to_contain_text('ข่าวไทย')
        self.assertEqual(self.page.locator('.unknown').count(),3)
        expect(self.page.locator('#health')).to_contain_text('เวลาที่ดึง ≠ เวลาที่ข่าวเกิดขึ้น')
        for a in self.page.locator('.report h2 a').all():
            self.assertTrue(a.get_attribute('href').startswith('https://example.com/2026/'))
            self.assertEqual(a.get_attribute('rel'),'noopener noreferrer')
    def test_02_search_and_empty_state(self):
        self.page.locator('#news-search').fill('ขนส่ง')
        expect(self.page.locator('.report:visible')).to_have_count(1)
        self.page.locator('#news-search').fill('no-match')
        expect(self.page.locator('.report:visible')).to_have_count(0)
        expect(self.page.locator('#no-results')).to_be_visible()
        self.page.locator('#news-search').fill('')
        expect(self.page.locator('.report:visible')).to_have_count(3)
    def test_03_no_storage_or_remote_requests(self):
        before=self.page.evaluate('JSON.stringify(localStorage)')
        self.page.locator('.provenance summary').first.click()
        self.page.locator('#news-source').select_option('test-source')
        self.page.locator('#news-search').fill('ไทย')
        self.assertEqual(self.page.evaluate('JSON.stringify(localStorage)'),before)
        self.assertTrue(all(u.startswith(self.url) and method=='GET' for u,method in self.requests),self.requests)
    def test_04_stale_source_timestamp_is_visible(self):
        self.page.locator('#health').evaluate("el=>el.dataset.lastSuccess='2020-01-01T00:00:00Z'")
        self.page.evaluate('updateAge()')
        expect(self.page.locator('#health-label')).to_contain_text('ข้อมูลอาจเก่า')
        self.assertIn('stale',self.page.locator('#health').get_attribute('class'))
    def test_05_seven_viewports_and_screenshots(self):
        geometry=[]
        for width,height in ((320,640),(360,800),(390,844),(768,1024),(1024,768),(1440,1000),(844,390)):
            self.page.set_viewport_size({'width':width,'height':height})
            self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth<=innerWidth'),str(width))
            geometry.append({'width':width,'height':height,'report':self.page.locator('.report').first.bounding_box()})
        self.page.set_viewport_size({'width':360,'height':800})
        self.page.screenshot(path=str(RESULTS/'news-mobile.png'),full_page=True)
        self.page.set_viewport_size({'width':1440,'height':1000})
        self.page.screenshot(path=str(RESULTS/'news-desktop.png'),full_page=True)
        (RESULTS/'geometry.json').write_text(json.dumps(geometry,indent=2))
    def test_06_keyboard_and_no_javascript_content(self):
        self.page.keyboard.press('Tab')
        self.assertEqual(self.page.evaluate('document.activeElement.className'),'skip')
        self.page.keyboard.press('Enter')
        self.page.locator('#news-search').focus();self.page.keyboard.type('test')
        self.assertEqual(self.page.locator('#news-search').input_value(),'test')
        context=self.browser.new_context(java_script_enabled=False)
        try:
            page=context.new_page();page.goto(self.url)
            expect(page.locator('.report')).to_have_count(3)
            expect(page.locator('.report h2 a').first).to_be_visible()
        finally:context.close()

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NewsBrowserTests))
    (RESULTS/'results.json').write_text(json.dumps({'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'status':'SAT' if result.wasSuccessful() else 'VIOL'},indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)
