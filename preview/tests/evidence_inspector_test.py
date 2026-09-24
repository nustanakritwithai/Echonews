"""UX-P0.2 native served-origin Chromium: inherit all 24 Room V2 cases unchanged.
Twelve new inspector methods. No offline rendering counted as browser integration.
"""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from room_v2_test import RoomV2Tests,RESULTS


class InspectorTests(RoomV2Tests):
    def claim(self,claim='c1',room='canal-demo'):
        self.go('/room/'+room)
        self.page.locator('[data-action=claim][data-id='+claim+']').click()
        self.page.locator('#modal.evidence-inspector').wait_for()

    def stage(self,expected):
        self.assertEqual(self.page.locator('#modal').get_attribute('data-inspect-stage'),expected)
        self.assertEqual(self.page.locator('dialog[open]').count(),1)
        self.assertEqual(self.page.locator('.ei-trail [aria-current=step]').count(),1)

    def test_25_full_trace_back_and_breadcrumb_preserve_room(self):
        self.claim();self.stage('claim')
        scroll=self.page.evaluate('scrollY')
        self.page.locator('[data-inspect=evidence][data-id=e1]').click();self.stage('evidence')
        self.assertIn('F-01',self.page.locator('.ei-scroll').inner_text())
        self.page.locator('#modal [data-inspect=source]').click();self.stage('source')
        self.assertIn('ห้องข่าว',self.page.locator('.ei-trail').inner_text())
        self.assertIn('ข้อกล่าวอ้าง',self.page.locator('.ei-trail').inner_text())
        self.assertIn('ต้นทาง v1',self.page.locator('#modal').inner_text())
        self.page.locator('[data-inspect=back]').click();self.stage('evidence')
        self.page.locator('[data-inspect=crumb][data-step=claim]').click();self.stage('claim')
        self.assertEqual(self.page.locator('#modal .evidencecard').count(),2)
        self.page.locator('[data-inspect=crumb][data-step=room]').click()
        self.assertFalse(self.page.locator('#modal').is_visible())
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'),'c1')
        self.assertLessEqual(abs(self.page.evaluate('scrollY')-scroll),3)

    def test_26_quick_source_path_retains_evidence_context(self):
        self.claim();self.page.locator('#modal [data-action=original][data-id=v2]').click();self.stage('source')
        self.page.locator('[data-inspect=back]').click();self.stage('evidence')
        self.assertIn('รายงานอีกจุดบริเวณสะพาน',self.page.locator('.ei-title').inner_text())
        self.page.locator('[data-inspect=back]').click();self.stage('claim')

    def test_27_unknown_has_no_invented_evidence_or_external_link(self):
        self.claim('c3');self.stage('claim')
        self.assertEqual(self.page.locator('#modal .evidencecard').count(),0)
        self.assertIn('ไม่ได้แปลว่าข้อกล่าวอ้างเป็นเท็จ',self.page.locator('#modal').inner_text())
        self.assertEqual(self.page.locator('#modal a[href^="http"]').count(),0)
        self.page.locator('[data-inspect=back]').click()
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'),'c3')

    def test_28_repeated_family_and_repost_keep_provenance_visible(self):
        self.claim('c2')
        self.page.locator('[data-inspect=evidence][data-id=e3]').click()
        self.assertIn('2 รายการใน F-01 ไม่ใช่ 2 แหล่งอิสระ',self.page.locator('#modal').inner_text())
        self.assertIn('ยังไม่ประเมิน',self.page.locator('#modal').inner_text())
        self.page.locator('#modal [data-inspect=source]').click()
        self.assertIn('นนท์',self.page.locator('.ei-original').inner_text())
        self.assertIn('อ้างต่อจาก v1',self.page.locator('.ei-original').inner_text())
        self.assertIn('ผมไม่ได้อยู่ในพื้นที่',self.page.locator('.voicecontent:visible').inner_text())

    def test_29_direct_evidence_and_direct_voice_do_not_fabricate_claim_context(self):
        self.go('/room/transit-demo')
        self.page.locator('.room-evidence-list > summary').click()
        self.page.locator('.room-evidence-list [data-action=evidence]').click();self.stage('evidence')
        self.assertNotIn('ข้อกล่าวอ้าง',self.page.locator('.ei-trail').inner_text())
        self.assertIn('ยังไม่ได้เลือกข้อกล่าวอ้าง',self.page.locator('.ei-scroll').inner_text())
        self.page.keyboard.press('Escape');self.layer('society')
        self.page.locator('#room-panel-society [data-action=original][data-id=v8]').click();self.stage('source')
        self.assertNotIn('หลักฐาน',self.page.locator('.ei-trail').inner_text())
        self.assertIn('ไม่มี URL',self.page.locator('.ei-scroll').inner_text())

    def test_30_inspector_reflows_and_controls_remain_inside_viewport(self):
        geometry=[]
        for width,height in ((320,640),(360,800),(390,844),(768,900),(1024,900),(1440,1000),(844,390)):
            self.page.set_viewport_size({'width':width,'height':height})
            self.claim()
            for stage in ('claim','evidence','source'):
                if stage=='evidence':self.page.locator('[data-inspect=evidence][data-id=e1]').click()
                if stage=='source':self.page.locator('#modal [data-inspect=source]').click()
                self.stage(stage)
                box=self.page.locator('#modal').bounding_box()
                self.assertGreaterEqual(box['x'],-1);self.assertGreaterEqual(box['y'],-1)
                self.assertLessEqual(box['x']+box['width'],width+1)
                self.assertLessEqual(box['y']+box['height'],height+1)
                self.assertTrue(self.page.locator('.ei-scroll').evaluate('el=>el.scrollWidth<=el.clientWidth'))
                for selector in ('#modal .close','.ei-footer button'):
                    control=self.page.locator(selector).bounding_box()
                    self.assertGreaterEqual(control['height'],44)
                    self.assertGreaterEqual(control['y'],0)
                    self.assertLessEqual(control['y']+control['height'],height+1)
                geometry.append({'width':width,'height':height,'stage':stage,'box':box})
            if width<900:self.assertLessEqual(abs(box['y']+box['height']-height),1)
            else:self.assertLessEqual(abs(box['x']+box['width']-width),1)
            self.page.keyboard.press('Escape')
        (RESULTS/'inspector-geometry.json').write_text(json.dumps(geometry,indent=2))

    def test_31_native_modal_keyboard_focus_and_escape(self):
        self.claim()
        self.assertEqual(self.page.evaluate('document.activeElement.id'),'modal-title')
        for _ in range(16):
            self.page.keyboard.press('Tab')
            self.assertTrue(self.page.evaluate('document.querySelector("#modal").contains(document.activeElement)'))
        for _ in range(16):
            self.page.keyboard.press('Shift+Tab')
            self.assertTrue(self.page.evaluate('document.querySelector("#modal").contains(document.activeElement)'))
        self.page.keyboard.press('Escape');self.page.wait_for_timeout(80)
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'),'c1')
        self.assertFalse(self.page.locator('body').evaluate('el=>el.classList.contains("inspector-open")'))

    def test_32_local_original_preserves_text_and_inert_markup(self):
        text='  ต้นฉบับ\n<img src=x onerror="window.ECHO_PWNED=true">  '
        self.compose(text)
        self.page.locator('#main [data-action=original]').click();self.stage('source')
        self.assertIn('<img src=x',self.page.locator('.ei-original .voicecontent').inner_text())
        self.assertEqual(self.page.locator('.ei-original img').count(),0)
        self.assertIn('ไม่ได้ส่งให้ผู้อื่น',self.page.locator('#modal').inner_text())
        self.assertFalse(self.page.evaluate('Boolean(window.ECHO_PWNED)'))
        self.page.keyboard.press('Escape')
        self.assertEqual(self.page.locator('#main .voicecard').count(),1)

    def test_33_reading_does_not_mutate_storage_reality_or_make_requests(self):
        self.go('/room/canal-demo');before=self.page.locator('.event-state').inner_html()
        saved=self.page.evaluate('JSON.stringify(localStorage)');requests=[]
        self.page.on('request',lambda r:requests.append(r.url))
        self.page.locator('[data-action=claim][data-id=c1]').click()
        self.page.locator('[data-inspect=evidence][data-id=e1]').click()
        self.page.locator('#modal [data-inspect=source]').click()
        self.page.locator('[data-inspect=back]').click();self.page.keyboard.press('Escape')
        self.assertEqual(self.page.evaluate('JSON.stringify(localStorage)'),saved)
        self.assertEqual(self.page.locator('.event-state').inner_html(),before)
        self.assertEqual(requests,[])
        self.assertIn("connect-src 'none'",self.page.locator('meta[http-equiv="Content-Security-Policy"]').get_attribute('content'))

    def test_34_route_change_and_rerender_release_modal_without_stale_focus(self):
        self.claim();self.go('/room/transit-demo')
        self.assertFalse(self.page.locator('#modal').is_visible())
        self.assertFalse(self.page.locator('body').evaluate('el=>el.classList.contains("inspector-open")'))
        self.page.locator('[data-action=claim][data-id=c4]').click();self.stage('claim')
        self.page.keyboard.press('Escape')
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'),'c4')
        self.page.locator('.bottomnav [data-action=compose]').click()
        self.assertFalse(self.page.locator('#modal').evaluate('el=>el.classList.contains("evidence-inspector")'))
        self.assertTrue(self.page.locator('#voice-form').is_visible())

    def test_35_inspector_reopen_and_scroll_does_not_lose_clicks(self):
        for _ in range(3):
            self.claim('c1')
            self.page.locator('[data-inspect=evidence][data-id=e2]').click();self.stage('evidence')
            self.page.locator('#modal [data-inspect=source]').click();self.stage('source')
            self.page.locator('#modal .close').click()
        self.claim('c3');self.assertIn('ยังไม่มีหลักฐาน',self.page.locator('#modal').inner_text())

    def test_36_visual_evidence_reduced_motion_and_forced_colors(self):
        for width,height,label in ((360,800,'mobile'),(1440,1000,'desktop')):
            self.page.set_viewport_size({'width':width,'height':height});self.claim()
            self.page.screenshot(path=str(RESULTS/f'inspector-{label}-claim.png'))
            self.page.locator('[data-inspect=evidence][data-id=e1]').click()
            self.page.screenshot(path=str(RESULTS/f'inspector-{label}-evidence.png'))
            self.page.locator('#modal [data-inspect=source]').click()
            self.page.screenshot(path=str(RESULTS/f'inspector-{label}-source.png'))
            self.page.emulate_media(reduced_motion='reduce',forced_colors='active')
            self.page.locator('[data-inspect=back]').click();self.stage('evidence')
            self.page.keyboard.press('Escape')
            self.page.emulate_media(reduced_motion='no-preference',forced_colors='none')


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(InspectorTests)
    ids=[t.id() for t in suite]
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report=dict(suite='Evidence Inspector served /Echonews/preview/',tests=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
        test_ids=ids,status='SAT' if result.wasSuccessful() else 'VIOL')
    (RESULTS/'inspector-browser-results.json').write_text(json.dumps(report,indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)
