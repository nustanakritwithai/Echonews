"""Deterministic safety/semantics gates; no network or external news in unit fixtures."""
import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect as n

NOW = n.date('2026-09-24T12:00:00Z')
SOURCE = dict(id='test-feed', publisherId='test-source', publisherName='แหล่งข้อมูลทดสอบ', label='ข่าวไทยทดสอบ',
              feedUrl='https://example.com/feed', hosts=['example.com'], articlePathPattern=r'^/2026/[0-9]+$',
              policyUrl='https://example.com/rss', excludeCategories=['ต่างประเทศ'], requireThaiTopic=True)

def rss(title='ข่าวประเทศไทยทดสอบ', link='https://example.com/2026/1', published='Thu, 24 Sep 2026 18:00:00 +0700', extra=''):
    return f'<rss version="2.0"><channel><item><title><![CDATA[{title}]]></title><link>{link}</link><pubDate>{published}</pubDate>{extra}</item></channel></rss>'.encode()

def snapshot(title='ข่าวประเทศไทยทดสอบ'):
    return n.collect([SOURCE], n.empty_snapshot(), NOW, lambda *a: rss(title))

class NewsTests(unittest.TestCase):
    def test_01_real_report_semantics_do_not_claim_fact_or_event(self):
        out=snapshot(); r=out['records'][0]
        self.assertEqual(r['evidenceState'],'UNKNOWN');self.assertEqual(r['eventMatchState'],'UNASSIGNED')
        self.assertEqual(r['publishedAt'],'2026-09-24T11:00:00Z');self.assertEqual(r['firstSeenAt'],n.iso(NOW))
        self.assertNotIn('description',r);self.assertNotIn('content',r)
    def test_02_no_article_body_or_images_are_copied(self):
        rows,_=n.parse_feed(rss(extra='<description>SECRET_FULL_ARTICLE</description><enclosure url="https://example.com/photo.jpg"/>'),SOURCE,NOW)
        self.assertNotIn('SECRET',json.dumps(rows));self.assertNotIn('photo.jpg',json.dumps(rows))
    def test_03_repeat_fetch_deduplicates_without_revisions(self):
        first=snapshot(); out=n.collect([SOURCE],first,NOW+timedelta(hours=1),lambda *a:rss())
        self.assertEqual(len(out['records']),1);self.assertEqual(len(out['records'][0]['revisions']),1)
        self.assertEqual(out['records'][0]['firstSeenAt'],first['records'][0]['firstSeenAt'])
        self.assertNotEqual(out['records'][0]['lastSeenAt'],first['records'][0]['lastSeenAt'])
    def test_04_title_change_is_observed_revision_not_silent_rewrite(self):
        first=snapshot(); old=copy.deepcopy(first)
        out=n.collect([SOURCE],first,NOW+timedelta(hours=1),lambda *a:rss('ข่าวประเทศไทยแก้พาดหัว'))
        self.assertEqual(first,old);self.assertEqual(len(out['records'][0]['revisions']),2)
        self.assertEqual(out['records'][0]['revisions'][0]['title'],old['records'][0]['title'])
    def test_05_multiple_feeds_same_publisher_are_not_independent_sources(self):
        other={**SOURCE,'id':'other-feed'}
        out=n.collect([SOURCE,other],n.empty_snapshot(),NOW,lambda *a:rss())
        self.assertEqual(len(out['records']),1);self.assertEqual(len(out['records'][0]['sourceFeedIds']),2)
    def test_06_missing_bad_naive_old_future_dates_are_not_assigned_now(self):
        for value in ('','garbage','2026-09-24T10:00:00','2026-09-25T00:00:00Z','2025-09-24T11:00:00Z'):
            rows,stats=n.parse_feed(rss(published=value),SOURCE,NOW)
            self.assertEqual(rows,[]);self.assertEqual(stats['skippedDate'],1)
    def test_07_uri_attack_matrix_is_rejected(self):
        for value in ('http://example.com/2026/1','https://evil.invalid/2026/1','javascript:alert(1)',
            'https://example.com@evil.invalid/2026/1','https://user@example.com/2026/1',
            'https://example.com:444/2026/1','https://example.com\\@evil.invalid/2026/1','https://example.com/2026/1\n'):
            with self.subTest(value=value):
                with self.assertRaises(n.NewsError):n.safe_url(value,SOURCE['hosts'])
    def test_08_entry_link_must_be_an_article_path(self):
        rows,stats=n.parse_feed(rss(link='https://example.com/redirect'),SOURCE,NOW)
        self.assertFalse(rows);self.assertEqual(stats['skippedUrl'],1)
    def test_09_tracking_params_are_removed_but_ids_preserved(self):
        self.assertEqual(n.safe_url('https://example.com/2026/1?utm_source=x&id=1#section',SOURCE['hosts']),'https://example.com/2026/1?id=1')
    def test_10_xml_entities_dtd_and_html_are_rejected(self):
        for raw in (b'<!DOCTYPE rss [<!ENTITY x "boom">]><rss/>',b'<html>not feed</html>',b'<rss>',b'\xff'):
            with self.assertRaises(n.NewsError):n.parse_feed(raw,SOURCE,NOW)
    def test_11_response_and_item_limits(self):
        with self.assertRaises(n.NewsError):n.parse_feed(b'x'*(n.MAX_BYTES+1),SOURCE,NOW)
        with self.assertRaises(n.NewsError):n.parse_feed(('<rss><channel>'+'<item/>'*1001+'</channel></rss>').encode(),SOURCE,NOW)
    def test_12_safe_plain_title_and_character_limit(self):
        rows,_=n.parse_feed(rss('<script>alert(1)</script><b>ไทย</b>'+'ก'*300),SOURCE,NOW)
        self.assertEqual(len(rows[0]['title']),180);self.assertTrue(rows[0]['titleTruncated'])
        self.assertNotIn('alert',rows[0]['title']);self.assertNotIn('<',rows[0]['title'])
    def test_13_foreign_and_non_thai_topic_are_excluded(self):
        for raw in (rss(extra='<category>ข่าวต่างประเทศ</category>'),rss(title='US market update')):
            rows,stats=n.parse_feed(raw,SOURCE,NOW);self.assertFalse(rows);self.assertEqual(stats['skippedScope'],1)
    def test_14_atom_publication_is_supported(self):
        raw=b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Thai news</title><link href="https://example.com/2026/3"/><published>2026-09-24T10:00:00Z</published></entry></feed>'
        rows,_=n.parse_feed(raw,{**SOURCE,'requireThaiTopic':False},NOW);self.assertEqual(len(rows),1)
    def test_15_single_source_failure_preserves_its_existing_records(self):
        first=snapshot(); other={**SOURCE,'id':'other-feed','feedUrl':'https://example.com/other'}
        def read(url,*_):
            if url==SOURCE['feedUrl']:raise RuntimeError('secret raw error')
            return rss(link='https://example.com/2026/2')
        out=n.collect([SOURCE,other],first,NOW+timedelta(hours=1),read)
        self.assertEqual(out['status'],'PARTIAL');self.assertEqual(len(out['records']),2)
        self.assertNotIn('secret',json.dumps(out))
    def test_16_all_sources_down_preserves_last_success_not_fresh(self):
        first=snapshot()
        def fail(*_):raise OSError('offline')
        out=n.collect([SOURCE],first,NOW+timedelta(hours=1),fail)
        self.assertEqual(out['status'],'STALE');self.assertEqual(out['lastSuccessfulFetchAt'],first['lastSuccessfulFetchAt'])
        self.assertEqual(out['records'],first['records'])
    def test_17_no_previous_and_no_sources_cannot_fabricate_news(self):
        with self.assertRaises(n.NewsError):n.collect([SOURCE],n.empty_snapshot(),NOW,lambda *a: (_ for _ in ()).throw(OSError()))
    def test_18_corrupt_previous_blocks_replacement(self):
        for raw in (b'{broken',b'{"schemaVersion":1,"mode":"SYNTHETIC","records":[]}'):
            with self.assertRaises(n.NewsError):n.previous_snapshot([SOURCE],lambda *a:raw)
    def test_19_only_404_can_bootstrap_previous(self):
        def missing(*a):raise urllib.error.HTTPError(n.PREVIOUS_URL,404,'missing',{},None)
        self.assertEqual(n.previous_snapshot([SOURCE],missing),n.empty_snapshot())
        def outage(*a):raise urllib.error.HTTPError(n.PREVIOUS_URL,503,'down',{},None)
        with self.assertRaises(n.NewsError):n.previous_snapshot([SOURCE],outage)
    def test_20_snapshot_rejects_fabricated_truth_and_id(self):
        for key,value in (('evidenceState','SUPPORTED'),('eventMatchState','MATCHED'),('id','bad')):
            data=snapshot();data['records'][0][key]=value
            with self.assertRaises(n.NewsError):n.validate_snapshot(data,[SOURCE])
    def test_21_old_reports_retire_from_rolling_view_without_fake_timestamps(self):
        first=snapshot(); future=NOW+timedelta(days=8)
        out=n.collect([SOURCE],first,future,lambda *a:b'<rss><channel/></rss>')
        self.assertEqual(out['records'],[])
    def test_22_render_is_escaped_and_read_only(self):
        data=snapshot();data['records'][0]['title']='<img src=x onerror=alert(1)>'
        rendered=n.render(data,[SOURCE])
        self.assertIn('&lt;img',rendered);self.assertNotIn('<img src=x',rendered)
        self.assertIn("connect-src 'none'",rendered);self.assertNotIn('<form',rendered)
        self.assertIn('ยังไม่ได้ตรวจยืนยัน',rendered);self.assertIn('08:15',rendered)
    def test_23_manifest_matches_four_published_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);n.write_output(snapshot(),[SOURCE],path)
            manifest=json.loads((path/'manifest.json').read_text())
            self.assertEqual(set(manifest),{'data.json','index.html','news.css','news.js'})
            for name,digest in manifest.items():self.assertEqual(hashlib.sha256((path/name).read_bytes()).hexdigest(),digest)
    def test_24_source_registry_is_explicit_and_not_article_driven(self):
        sources=n.registry();self.assertGreaterEqual(len(sources),3)
        self.assertEqual(len({x['publisherId'] for x in sources[:3]}),1)
        for src in sources:self.assertTrue(src['feedUrl'].startswith('https://'))
    def test_25_private_dns_and_cross_host_redirect_denied(self):
        with patch.object(n.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(n.NewsError):n.public_dns('example.com')
        request=n.urllib.request.Request('https://example.com/feed')
        with self.assertRaises(n.NewsError):n.SafeRedirect(['example.com']).redirect_request(request,None,302,'',{},'https://evil.invalid/feed')

if __name__=='__main__':unittest.main(verbosity=2)
