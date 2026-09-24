"""UX-P0.3 native served-origin browser suite: all 37 Inspector cases unchanged.
Twelve new feed cases. CI uses a real loopback server, not in-memory render mocks.
"""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_inspector_test import InspectorTests,RESULTS


class FeedV2Tests(InspectorTests):
    def card(self,room='canal-demo'):
        return self.page.locator('.feed-event[data-room="'+room+'"]')

    def feed_claim(self,room='canal-demo',claim='c1'):
        self.go('/')
        self.card(room).locator('[data-action=feed-claim][data-id='+claim+']').click()
        self.page.locator('#modal.evidence-inspector').wait_for()

    def reality_text(self,room='canal-demo'):
        return self.card(room).locator('.feed-reality').inner_text()

    def test_38_claim_state_unknown_before_decoration_and_society(self):
        for room,counts in [('canal-demo',[1,1,1]),('transit-demo',[1,0,1]),('model-demo',[0,0,1])]:
            c=self.card(room)
            self.assertEqual(c.locator('.feed-state-count b').all_text_contents(),list(map(str,counts)))
            self.assertFalse(c.locator('.feed-art').evaluate('e=>e.open'))
            self.assertTrue(c.evaluate('e=>e.querySelector(".feed-reality").getBoundingClientRect().bottom<=e.querySelector(".feed-society").getBoundingClientRect().top'))
            self.assertIn('ยังไม่ประเมิน',c.locator('.feed-freshness').inner_text())
        self.assertIn('ยังไม่มีข้อกล่าวอ้างที่มีข้อมูลรองรับ',self.card('model-demo').locator('.feed-supported').inner_text())

    def test_39_mobile_first_card_title_state_and_unknown_above_navigation(self):
        self.page.set_viewport_size({'width':360,'height':800});self.go('/')
        geometry={}
        nav=self.page.locator('.bottomnav').bounding_box()
        for selector in ('.cardlink h2','.feed-state-heading','.feed-state-counts','.feed-unknown'):
            box=self.card().locator(selector).bounding_box();geometry[selector]=box
            self.assertGreaterEqual(box['y'],0)
            self.assertLessEqual(box['y']+box['height'],nav['y'],selector)
        self.page.screenshot(path=str(RESULTS/'feed-v2-360-first.png'))
        (RESULTS/'feed-v2-first-viewport.json').write_text(json.dumps({'viewport':[360,800],'nav':nav,'elements':geometry},indent=2))

    def test_40_direct_feed_claim_reaches_original_without_changing_route(self):
        self.feed_claim();self.stage('claim')
        self.page.locator('#modal [data-action=original][data-id=v1]').click();self.stage('source')
        self.assertIn('ฟ้า',self.page.locator('.ei-original').inner_text())
        self.assertIn('หน้าตลาดมีน้ำ',self.page.locator('.voicecontent:visible').inner_text())
        self.assertEqual(self.page.evaluate('location.hash'),'#/')
        self.page.keyboard.press('Escape')
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.action'),'feed-claim')
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'),'c1')

    def test_41_unknown_from_feed_does_not_invent_sources(self):
        self.feed_claim(claim='c3');self.stage('claim')
        self.assertEqual(self.page.locator('#modal .evidencecard').count(),0)
        self.assertIn('ไม่ได้แปลว่าข้อกล่าวอ้างเป็นเท็จ',self.page.locator('#modal').inner_text())
        self.page.keyboard.press('Escape')
        self.feed_claim('transit-demo','c4')
        self.assertIn('เปลี่ยนจุดรับรถ',self.page.locator('#modal').inner_text())
        self.assertNotIn('หน้าตลาดมีน้ำ',self.page.locator('#modal').inner_text())

    def test_42_latest_is_fictional_record_not_live_freshness(self):
        self.assertIn('18:10',self.card().locator('.feed-latest').inner_text())
        self.assertIn('บันทึกท้ายเรื่องสมมติ',self.card().locator('.feed-latest').inner_text())
        self.assertIn('ยังไม่มีข้อมูลใหม่เพียงพอ',self.card().locator('.feed-latest').inner_text())
        self.assertEqual(self.page.locator('.feed-freshness[data-freshness=UNKNOWN]').count(),3)
        self.assertEqual(self.page.locator('.feed [data-freshness=FRESH]').count(),0)

    def test_43_room_summary_and_feed_summary_remain_consistent(self):
        for room in ('canal-demo','transit-demo','model-demo'):
            self.go('/');c=self.card(room)
            counts=c.locator('.feed-state-count b').all_text_contents()
            unknown=c.locator('.feed-unknown .feed-point-text').inner_text()
            c.locator('.cardlink').click()
            self.assertEqual(self.page.locator('.state-metric strong').all_text_contents(),counts)
            self.assertIn(unknown,self.page.locator('.top-unknown').inner_text())

    def test_44_local_post_changes_only_society_not_state_or_latest(self):
        self.go('/');before=self.reality_text();order=self.page.locator('.feed-event').evaluate_all('es=>es.map(e=>e.dataset.room)')
        self.compose('LOCAL_FEED_STATE_INVARIANT',True)
        self.go('/')
        self.assertEqual(self.reality_text(),before)
        self.assertIn('7 เสียง',self.card().locator('.feed-society').inner_text())
        self.assertEqual(self.page.locator('.feed-event').evaluate_all('es=>es.map(e=>e.dataset.room)'),order)
        self.go('/me');self.page.locator('[data-action=visibility]').click();self.go('/')
        self.assertEqual(self.reality_text(),before)
        self.assertIn('6 เสียง',self.card().locator('.feed-society').inner_text())

    def test_45_feed_inspection_does_not_write_storage_or_request_network(self):
        self.go('/');before=self.page.evaluate('JSON.stringify({...localStorage})');requests=[]
        self.page.on('request',lambda r:requests.append(r.url))
        self.card().locator('[data-action=feed-claim][data-id=c1]').click()
        self.page.locator('[data-inspect=evidence][data-id=e1]').click()
        self.page.locator('#modal [data-inspect=source]').click()
        self.page.keyboard.press('Escape')
        self.assertEqual(self.page.evaluate('JSON.stringify({...localStorage})'),before)
        self.assertEqual(requests,[])

    def test_46_following_search_and_empty_state_keep_new_cards(self):
        self.card().locator('[data-action=follow]').click();self.go('/following')
        self.assertEqual(self.page.locator('.feed-event').count(),1)
        self.assertTrue(self.card().locator('.feed-reality').is_visible())
        self.page.reload();self.page.wait_for_selector('.feed-event')
        self.assertEqual(self.page.locator('.feed-event').count(),1)
        self.page.locator('#search').fill('NO_MATCH_FEED_NEEDLE')
        self.assertEqual(self.page.locator('.feed-event').count(),0)
        self.page.locator('[data-action=clear-search]').click()
        self.assertEqual(self.page.locator('.feed-event').count(),3)

    def test_47_reflow_all_cards_and_controls_across_viewports(self):
        geometry=[]
        for width,height in ((320,640),(360,800),(390,844),(768,900),(1024,900),(1440,1000),(844,390)):
            self.page.set_viewport_size({'width':width,'height':height});self.go('/')
            self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth<=innerWidth'))
            for room in ('canal-demo','transit-demo','model-demo'):
                c=self.card(room)
                self.assertTrue(c.evaluate('e=>e.scrollWidth<=e.clientWidth'))
                for selector in ('[data-action=feed-claim]','.cardfoot a','.cardfoot button','.feed-art summary'):
                    for control in c.locator(selector).all():
                        box=control.bounding_box();self.assertGreaterEqual(box['height'],44)
                        self.assertGreaterEqual(box['x'],0);self.assertLessEqual(box['x']+box['width'],width+1)
                c.locator('.feed-art summary').click()
                self.assertTrue(c.locator('.landscape').is_visible())
                self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth<=innerWidth'))
                c.locator('.feed-art summary').click()
                geometry.append({'viewport':[width,height],'room':room,'card':c.bounding_box()})
        (RESULTS/'feed-v2-geometry.json').write_text(json.dumps(geometry,indent=2))

    def test_48_keyboard_inspector_from_feed_returns_to_opener(self):
        self.go('/');button=self.card().locator('[data-action=feed-claim][data-id=c3]')
        button.focus();self.page.keyboard.press('Enter');self.stage('claim')
        self.assertTrue(self.page.locator('#modal').is_visible())
        self.page.keyboard.press('Escape')
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'),'c3')
        self.assertEqual(self.page.evaluate('location.hash'),'#/')

    def test_49_screenshots_and_family_warning_without_independence_claim(self):
        self.go('/')
        self.assertIn('3 รายการอ้างอิง · 2 สายต้นทางตัวอย่าง',self.card().locator('.feed-provenance').inner_text())
        self.assertIn('ยังไม่ประเมินความเป็นอิสระ',self.card().locator('.feed-provenance').inner_text())
        self.assertIn('จำนวนเสียง ≠ หลักฐาน',self.card().locator('.feed-society').inner_text())
        for width,height,name in ((390,844,'mobile'),(1440,1000,'desktop')):
            self.page.set_viewport_size({'width':width,'height':height});self.page.evaluate('scrollTo(0,0)')
            self.page.screenshot(path=str(RESULTS/('feed-v2-'+name+'.png')),full_page=True)
        self.card().locator('[data-action=feed-claim][data-id=c1]').click()
        self.page.screenshot(path=str(RESULTS/'feed-v2-direct-inspector.png'))


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FeedV2Tests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (RESULTS/'feed-v2-browser-results.json').write_text(json.dumps({'suite':'native Chromium feed + Room + Inspector',
        'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'status':'SAT' if result.wasSuccessful() else 'VIOL'},indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)
