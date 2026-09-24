"""Real served-origin Chromium gate for UX-P0.1, never the offline layout harness.

Nine original browser cases inherited unchanged; cases 02/05/07 retain their
assertions with navigation updated for Reality-first tabs. Twelve new UX cases.
"""
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
from playwright.sync_api import sync_playwright

sys.path.insert(0,str(Path(__file__).resolve().parent))
from browser_test import BrowserTests, Quiet, ROOT, RESULTS

ROOMS = ('canal-demo','transit-demo','model-demo')
LAYERS = ('reality','society','timeline')


class RoomV2Tests(BrowserTests):
    @classmethod
    def setUpClass(cls):
        cls.host=tempfile.TemporaryDirectory()
        os.symlink(ROOT.parent,Path(cls.host.name)/'Echonews',target_is_directory=True)
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=cls.host.name))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url=f'http://127.0.0.1:{cls.server.server_port}/Echonews/preview/'
        cls.pw=sync_playwright().start()
        executable=None if os.environ.get('ECHO_USE_BUNDLED_BROWSER') else (os.environ.get('ECHO_CHROMIUM') or shutil.which('chromium'))
        cls.browser=cls.pw.chromium.launch(headless=True,**({'executable_path':executable} if executable else {}),args=['--no-sandbox'])

    def layer(self,key):
        self.page.locator('#room-tab-'+key).click()
        self.assertTrue(self.page.locator('#room-panel-'+key).is_visible())

    def test_02_room_tabs_and_source_drilldown(self):
        self.go('/room/canal-demo')
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),6)
        self.page.locator('[data-action=claim][data-id=c1]').click()
        self.assertTrue(self.page.locator('#modal').is_visible())
        self.page.locator('#modal [data-action=original]').first.click()
        self.assertIn('ต้นทาง v1',self.page.locator('#modal').inner_text())
        self.page.keyboard.press('Escape')
        self.assertFalse(self.page.locator('#modal').is_visible())
        self.page.locator('.room-evidence-list > summary').click()
        self.assertEqual(self.page.locator('#room-body .evidencecard:visible').count(),3)
        self.layer('timeline')
        self.assertEqual(self.page.locator('.moment:visible').count(),4)

    def test_05_local_room_voice_reloads_and_withdraws(self):
        self.compose('LOCAL_ROOM_POST',True)
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),7)
        self.assertIn('7 เสียง',self.page.locator('#room-count').inner_text())
        self.page.reload();self.page.wait_for_selector('#room-tab-society');self.layer('society')
        self.assertEqual(self.page.locator('#room-body .voicecard:visible').count(),7)
        self.go('/me');self.page.locator('[data-action=visibility]').click()
        self.assertEqual(self.page.locator('#main .voicecard').count(),1)
        self.go('/room/canal-demo')
        self.assertEqual(self.page.locator('#room-body .voicecard').count(),6)

    def test_07_voice_type_filter(self):
        self.go('/room/canal-demo');self.layer('society')
        self.page.locator('[data-action=kind][data-value=question]').click()
        self.assertEqual(self.page.locator('#room-body .voicecard:visible').count(),1)
        self.page.locator('[data-action=kind][data-value=all]').click()
        self.assertEqual(self.page.locator('#room-body .voicecard:visible').count(),6)

    def test_13_all_rooms_show_title_state_unknown_and_switch_in_first_mobile_viewport(self):
        self.page.set_viewport_size({'width':360,'height':800})
        geometry={}
        for room in ROOMS:
            with self.subTest(room=room):
                self.go('/room/'+room)
                self.page.evaluate('window.scrollTo(0,0)')
                self.page.wait_for_timeout(60)
                bottom=self.page.locator('.bottomnav').bounding_box()['y']
                boxes={}
                for selector in ('.room-heading h1','.event-state','.top-unknown','.room-segments'):
                    box=self.page.locator(selector).bounding_box();boxes[selector]=box
                    self.assertGreaterEqual(box['y'],0)
                    self.assertLessEqual(box['y']+box['height'],bottom,selector+' '+room)
                self.assertIn('ข้อมูลจำลอง',self.page.locator('.notice').inner_text())
                self.assertIn('บันทึกเฉพาะเครื่องนี้',self.page.locator('.notice').inner_text())
                self.assertEqual(self.page.locator('.freshness').get_attribute('data-freshness'),'UNKNOWN')
                self.assertTrue(self.page.locator('#room-panel-reality').is_visible())
                self.assertFalse(self.page.locator('#room-panel-society').is_visible())
                self.page.screenshot(path=str(RESULTS/('room-v2-360-'+room+'.png')))
                geometry[room]=boxes
        (RESULTS/'room-v2-first-viewport.json').write_text(json.dumps(geometry,indent=2))

    def test_14_all_rooms_and_layers_reflow_without_horizontal_overflow(self):
        for width,height in ((320,800),(360,800),(390,844),(768,900),(1024,900),(1440,1080),(844,390)):
            self.page.set_viewport_size({'width':width,'height':height})
            for room in ROOMS:
                self.go('/room/'+room)
                for layer in LAYERS:
                    self.layer(layer)
                    self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth<=innerWidth'),f'{width} {room} {layer}')

    def test_15_tabs_keyboard_semantics_and_panel_focus(self):
        self.go('/room/canal-demo')
        self.page.locator('#room-tab-reality').focus()
        for key,layer in (('ArrowRight','society'),('End','timeline'),('Home','reality'),('ArrowLeft','timeline')):
            self.page.keyboard.press(key)
            tab=self.page.locator('#room-tab-'+layer)
            self.assertEqual(tab.get_attribute('aria-selected'),'true')
            self.assertEqual(self.page.evaluate('document.activeElement.id'),'room-tab-'+layer)
            self.assertEqual(self.page.locator('[role=tab][tabindex="0"]').count(),1)
            self.assertEqual(self.page.locator('[role=tabpanel]:visible').count(),1)
            panel=self.page.locator('#'+tab.get_attribute('aria-controls'))
            self.assertTrue(panel.is_visible())
            self.assertEqual(panel.get_attribute('aria-labelledby'),'room-tab-'+layer)
        self.page.keyboard.press('Tab')
        self.assertEqual(self.page.evaluate('document.activeElement.id'),'room-panel-timeline')

    def test_16_sticky_context_and_focus_are_not_obscured(self):
        self.page.set_viewport_size({'width':360,'height':800})
        self.go('/room/canal-demo');self.layer('society')
        self.page.evaluate("scrollTo(0,document.querySelector('.room-sticky-marker').getBoundingClientRect().top+scrollY+200)")
        self.page.locator('.room-sticky.is-stuck').wait_for(state='visible')
        box=self.page.locator('.room-sticky').bounding_box()
        self.assertLessEqual(abs(box['y']),2);self.assertLessEqual(box['height'],132)
        self.assertTrue(self.page.locator('.room-compact').is_visible())
        button=self.page.locator('#room-panel-society [data-action=original]').first
        button.focus();self.page.wait_for_timeout(80)
        bounds=button.bounding_box();bar=self.page.locator('.room-sticky').bounding_box()
        self.assertGreaterEqual(bounds['y'],bar['y']+bar['height'])
        bottom=self.page.locator('.bottomnav').bounding_box()['y']
        self.assertLessEqual(bounds['y']+bounds['height'],bottom)
        self.page.screenshot(path=str(RESULTS/'room-v2-mobile-sticky.png'))
        self.layer('reality')
        self.assertTrue(self.page.locator('#room-panel-reality').is_visible())

    def test_17_two_step_claim_to_original_and_escape_returns_focus(self):
        self.go('/room/canal-demo')
        trigger=self.page.locator('[data-action=claim][data-id=c1]')
        trigger.click()
        self.assertEqual(self.page.locator('#modal .evidencecard').count(),2)
        self.page.locator('#modal [data-action=original]').first.click()
        self.assertIn('ต้นทาง v1',self.page.locator('#modal').inner_text())
        self.assertIn('การอนุมัติข้อเท็จจริง: ไม่มี',self.page.locator('#modal').inner_text())
        self.page.keyboard.press('Escape');self.page.wait_for_timeout(60)
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'),'c1')
        self.page.locator('[data-action=claim][data-id=c3]').click()
        self.assertTrue(self.page.locator('#modal').is_visible())
        self.assertEqual(self.page.locator('#modal .evidencecard').count(),0)
        self.assertIn('ไม่มีหลักฐาน',self.page.locator('#modal').inner_text())

    def test_18_new_local_voices_never_change_reality_or_freshness(self):
        self.go('/room/canal-demo')
        before=self.page.locator('.event-state').inner_html()
        self.compose('UX_LOCAL_OBSERVATION_ONE',True)
        self.compose('UX_LOCAL_OBSERVATION_TWO',True)
        self.assertTrue(self.page.locator('#room-panel-society').is_visible())
        self.assertEqual(self.page.locator('.voicecard:visible').count(),8)
        self.assertEqual(self.page.locator('.event-state').inner_html(),before)
        self.page.reload();self.page.wait_for_selector('.event-state')
        self.assertEqual(self.page.locator('.event-state').inner_html(),before)
        self.assertTrue(self.page.locator('#room-panel-reality').is_visible())
        self.layer('society')
        self.assertIn('จำนวนเสียง ≠ จำนวนหลักฐาน ≠ ความจริง',self.page.locator('.society-boundary').inner_text())
        self.assertEqual(self.page.locator('.voicecard:visible').count(),8)

    def test_19_filter_and_follow_rerenders_preserve_society_and_focus(self):
        self.go('/room/canal-demo');self.layer('society')
        self.page.locator('[data-action=kind][data-value=question]').click()
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.value'),'question')
        self.assertTrue(self.page.locator('#room-panel-society').is_visible())
        self.page.locator('.room-actions-v2 [data-action=follow]').click()
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.action'),'follow')
        self.assertEqual(self.page.locator('#room-tab-society').get_attribute('aria-selected'),'true')
        self.assertEqual(self.page.locator('.voicecard:visible').count(),1)
        self.assertTrue(self.page.evaluate("JSON.parse(localStorage.getItem('echo.preview.v1')).follows.includes('canal-demo')"))

    def test_20_view_navigation_does_not_write_storage_or_make_network_posts(self):
        self.go('/room/canal-demo');before=self.page.evaluate('JSON.stringify(localStorage)')
        requests=[];self.page.on('request',lambda r:requests.append((r.url,r.method)))
        for layer in ('society','timeline','reality'):self.layer(layer)
        self.page.locator('.room-latest > summary').click()
        self.assertIn('ไม่ใช่เวลาที่ระบบเพิ่งอัปเดต',self.page.locator('.room-latest').inner_text())
        self.page.locator('.room-evidence-list > summary').click()
        self.page.locator('.room-evidence-list [data-action=original]').first.click()
        self.page.keyboard.press('Escape')
        self.assertEqual(self.page.evaluate('JSON.stringify(localStorage)'),before)
        self.assertTrue(all(url.startswith(self.url) and method=='GET' for url,method in requests),requests)
        self.assertIn("connect-src 'none'",self.page.locator('meta[http-equiv="Content-Security-Policy"]').get_attribute('content'))

    def test_21_route_changes_reset_views_and_search_remains_available(self):
        for room in ROOMS:
            self.go('/room/'+room);self.layer('society')
        self.go('/room/canal-demo')
        self.assertEqual(self.page.locator('#room-tab-reality').get_attribute('aria-selected'),'true')
        self.page.locator('#search').fill('เส้นทางรถชุมชน')
        self.page.wait_for_selector('.feed .card')
        self.assertFalse(self.page.locator('#app').evaluate("el=>el.classList.contains('room-mode')"))
        self.assertEqual(self.page.locator('.room-segments').count(),0)
        self.assertEqual(self.page.locator('.feed .card[data-room=transit-demo]').count(),1)

    def test_22_primary_controls_and_equal_weight_unknown_are_readable(self):
        self.page.set_viewport_size({'width':360,'height':800});self.go('/room/canal-demo')
        for selector in ('.room-segments button','.room-claims button','.room-latest > summary','.room-actions-v2 button'):
            for control in self.page.locator(selector).all():
                box=control.bounding_box()
                self.assertGreaterEqual(box['height'],44,selector)
                self.assertGreaterEqual(box['width'],44,selector)
        sizes=self.page.locator('.state-metric strong').evaluate_all("els=>els.map(el=>[getComputedStyle(el).fontSize,getComputedStyle(el).fontWeight])")
        self.assertEqual(sizes[0],sizes[2])
        self.assertIn('ยังไม่ทราบ',self.page.locator('.top-unknown').inner_text())
        self.assertEqual([x.inner_text() for x in self.page.locator('.state-metric strong').all()],['1','1','1'])

    def test_23_local_storage_failure_does_not_claim_save_success(self):
        self.go('/room/canal-demo');before=self.page.locator('.event-state').inner_html()
        self.page.evaluate("() => { Storage.prototype.setItem=function(){throw new DOMException('Fixture quota','QuotaExceededError')}; }")
        self.page.locator('.bottomnav [data-action=compose]').click()
        self.page.locator('#voice-text').fill('SHOULD_NOT_SAVE')
        self.page.locator('#include-room').check()
        self.page.locator('#voice-form button[type=submit]').click()
        self.assertTrue(self.page.locator('#modal').is_visible())
        self.assertIn('บันทึกในเบราว์เซอร์ไม่สำเร็จ',self.page.locator('#form-error').inner_text())
        self.assertIsNone(self.page.evaluate("localStorage.getItem('echo.preview.v1')"))
        self.page.keyboard.press('Escape')
        self.assertEqual(self.page.locator('.event-state').inner_html(),before)

    def test_24_desktop_and_mobile_visual_evidence_and_reduced_motion(self):
        self.page.set_viewport_size({'width':1440,'height':1080});self.go('/room/canal-demo')
        self.page.screenshot(path=str(RESULTS/'room-v2-desktop-reality.png'),full_page=True)
        self.layer('society');self.page.screenshot(path=str(RESULTS/'room-v2-desktop-society.png'),full_page=True)
        self.page.set_viewport_size({'width':360,'height':800})
        self.go('/');self.go('/room/canal-demo');self.layer('society')
        self.page.screenshot(path=str(RESULTS/'room-v2-mobile-society.png'),full_page=True)
        self.page.emulate_media(reduced_motion='reduce',forced_colors='active')
        self.layer('timeline');self.layer('reality')
        self.assertTrue(self.page.locator('#room-panel-reality').is_visible())
        self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth<=innerWidth'))


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RoomV2Tests)
    ids=[t.id() for t in suite]
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report=dict(suite='Room V2 served /Echonews/preview/',tests=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
        test_ids=ids,status='SAT' if result.wasSuccessful() else 'VIOL')
    (RESULTS/'room-v2-browser-results.json').write_text(json.dumps(report,indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)
