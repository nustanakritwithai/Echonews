"""Real Chromium tests under /Echonews/, no internet and no backend required."""
import functools, http.server, json, os, pathlib, shutil, tempfile, threading, unittest
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[1]
RESULTS=ROOT/'results'
RESULTS.mkdir(exist_ok=True)
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self,*args): pass
class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host=tempfile.TemporaryDirectory()
        os.symlink(ROOT,pathlib.Path(cls.host.name)/'Echonews',target_is_directory=True)
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=cls.host.name))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url=f'http://127.0.0.1:{cls.server.server_port}/Echonews/'
        cls.pw=sync_playwright().start()
        executable=None if os.environ.get('ECHO_USE_BUNDLED_BROWSER') else (os.environ.get('ECHO_CHROMIUM') or shutil.which('chromium'))
        cls.browser=cls.pw.chromium.launch(headless=True,**({'executable_path':executable} if executable else {}),args=['--no-sandbox'])
    @classmethod
    def tearDownClass(cls):
        cls.browser.close();cls.pw.stop();cls.server.shutdown();cls.host.cleanup()
    def setUp(self):
        self.context=self.browser.new_context(viewport={'width':390,'height':844},device_scale_factor=1)
        self.page=self.context.new_page();self.errors=[]
        self.page.on('pageerror',lambda e:self.errors.append(str(e)))
        self.page.on('console',lambda e:self.errors.append(e.text) if e.type=='error' else None)
        self.page.goto(self.url);self.page.wait_for_selector('.feed .card')
    def tearDown(self):
        self.context.close();self.assertEqual(self.errors,[])
    def go(self,route):
        self.page.goto(self.url+'#'+route)
        self.page.wait_for_timeout(80)
    def compose(self,text,include=False):
        self.page.locator('.bottomnav [data-action=compose]').click()
        self.page.locator('#voice-text').fill(text)
        if include:self.page.locator('#include-room').check()
        self.page.locator('#voice-form button[type=submit]').click()
        self.page.wait_for_timeout(100)
    def test_01_mobile_feed_and_no_overflow(self):
        self.assertEqual(self.page.locator('.feed .card').count(),3)
        self.assertIn('ข้อมูลจำลอง',self.page.locator('.notice').inner_text())
        for width in [320,360,390,700,1280,1440]:
            self.page.set_viewport_size({'width':width,'height':900})
            self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth<=innerWidth'),f'overflow {width}')
    def test_02_room_tabs_and_source_drilldown(self):
        self.go('/room/canal-demo')
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),6)
        self.page.locator('[data-action=claim][data-id=c1]').click()
        self.assertTrue(self.page.locator('#modal').is_visible())
        self.page.locator('#modal [data-action=original]').first.click()
        self.assertIn('ต้นทาง v1',self.page.locator('#modal').inner_text())
        self.page.keyboard.press('Escape')
        self.assertFalse(self.page.locator('#modal').is_visible())
        self.page.locator('[data-action=tab][data-value=evidence]').click()
        self.assertEqual(self.page.locator('#room-body .evidencecard').count(),3)
        self.page.locator('[data-action=tab][data-value=timeline]').click()
        self.assertEqual(self.page.locator('.moment').count(),4)
    def test_03_follow_reload_and_unfollow(self):
        self.page.locator('.feed [data-action=follow]').first.click()
        self.go('/following')
        self.assertEqual(self.page.locator('.feed .card').count(),1)
        self.page.reload();self.page.wait_for_selector('.feed .card')
        self.assertEqual(self.page.locator('.feed .card').count(),1)
        self.page.locator('.feed [data-action=follow]').click()
        self.assertEqual(self.page.locator('.feed .card').count(),0)
    def test_04_draft_excluded_from_room_search_counts(self):
        self.compose('UNIQUE_PRIVATE_LOCAL_DRAFT')
        self.assertEqual(self.page.locator('#main .voicecard').count(),1)
        self.go('/room/canal-demo')
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),6)
        self.assertNotIn('UNIQUE_PRIVATE_LOCAL_DRAFT',self.page.locator('#main').inner_text())
        self.go('/')
        self.page.locator('#search').fill('UNIQUE_PRIVATE_LOCAL_DRAFT')
        self.assertEqual(self.page.locator('.feed .card').count(),0)
    def test_05_local_room_voice_reloads_and_withdraws(self):
        self.compose('LOCAL_ROOM_POST',True)
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),7)
        self.assertIn('7 เสียง',self.page.locator('#room-count').inner_text())
        self.page.reload();self.page.wait_for_selector('#room-body .voicecard')
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),7)
        self.go('/me');self.page.locator('[data-action=visibility]').click()
        self.assertEqual(self.page.locator('#main .voicecard').count(),1)
        self.go('/room/canal-demo')
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),6)
    def test_06_xss_text_not_markup(self):
        payload='<img src=x onerror="window.ECHO_PWNED=true">'
        self.compose(payload,True)
        self.assertEqual(self.page.locator('#room-body .voicecontent img').count(),0)
        self.assertFalse(self.page.evaluate('Boolean(window.ECHO_PWNED)'))
        self.assertIn(payload,self.page.locator('#room-body').inner_text())
    def test_07_voice_type_filter(self):
        self.go('/room/canal-demo')
        self.page.locator('[data-action=kind][data-value=question]').click()
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),1)
        self.page.locator('[data-action=kind][data-value=all]').click()
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),6)
    def test_08_unknown_route_graceful(self):
        self.go('/room/no-such-room');self.assertIn('ไม่พบห้องนี้',self.page.locator('#main').inner_text())
    def test_09_storage_corruption_preserved_and_reset(self):
        self.page.evaluate("localStorage.setItem('echo.preview.v1','{broken')")
        self.page.reload();self.page.wait_for_selector('.notice')
        self.assertIn('อ่านข้อมูลทดลองเดิมไม่ได้',self.page.locator('.notice').inner_text())
        self.assertEqual(self.page.evaluate("localStorage.getItem('echo.preview.v1')"),'{broken')
        self.page.on('dialog',lambda d:d.accept());self.go('/about')
        self.page.locator('[data-action=reset]').click()
        self.assertIsNone(self.page.evaluate("localStorage.getItem('echo.preview.v1')"))
    def test_10_form_validation_and_opt_in_default(self):
        self.page.locator('.bottomnav [data-action=compose]').click()
        self.assertFalse(self.page.locator('#include-room').is_checked())
        self.page.locator('#voice-text').fill('ก'*1001)
        self.page.locator('#voice-form button[type=submit]').click()
        self.assertTrue(self.page.locator('#modal').is_visible())
        self.assertIn('1,000',self.page.locator('#form-error').inner_text())
        self.assertIsNone(self.page.evaluate("localStorage.getItem('echo.preview.v1')"))
    def test_11_delete_keeps_other_site_storage(self):
        self.page.evaluate("localStorage.setItem('OTHER_PROJECT','keep')")
        self.compose('DELETE_THIS')
        self.page.on('dialog',lambda d:d.accept())
        self.page.locator('[data-action=delete]').click()
        self.assertEqual(self.page.locator('#main .voicecard').count(),0)
        self.assertEqual(self.page.evaluate("localStorage.getItem('OTHER_PROJECT')"),'keep')
    def test_12_screenshots_and_no_external_requests(self):
        requests=[];self.page.on('request',lambda r:requests.append(r.url))
        self.page.reload();self.page.wait_for_selector('.feed .card')
        self.page.screenshot(path=str(RESULTS/'mobile-feed.png'),full_page=True)
        self.go('/room/canal-demo')
        self.page.screenshot(path=str(RESULTS/'mobile-room.png'),full_page=True)
        self.page.set_viewport_size({'width':1440,'height':1080});self.go('/')
        self.page.screenshot(path=str(RESULTS/'desktop-feed.png'),full_page=True)
        self.assertTrue(all(u.startswith(self.url) for u in requests),requests)
if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(BrowserTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (RESULTS/'browser_results.json').write_text(json.dumps({'suite':'Chromium /Echonews/','tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'status':'SAT' if result.wasSuccessful() else 'VIOL'},indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)
