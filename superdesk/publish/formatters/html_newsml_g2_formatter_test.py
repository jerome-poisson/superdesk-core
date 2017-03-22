
import io
import os
import tempfile
from lxml import etree
from unittest import mock

from superdesk.utc import utcnow
from superdesk.tests import TestCase
from .html_newsml_g2_formatter import HTMLNewsMLG2Formatter


class HTMLNewsmlG2FormatterTestCase(TestCase):

    article = {
        'guid': 'tag:aap.com.au:20150613:12345',
        '_current_version': 1,
        'anpa_category': [
            {
                'qcode': 'a',
                'name': 'Australian General News'
            }
        ],
        'source': 'AAP',
        'headline': 'This is a test headline',
        'byline': 'joe',
        'slugline': 'slugline',
        'subject': [{'qcode': '02011001', 'name': 'international court or tribunal'},
                    {'qcode': '02011002', 'name': 'extradition'}],
        'anpa_take_key': 'take_key',
        'unique_id': '1',
        'body_html': '<p>The story body <b>HTML</b></p><p>another paragraph</p><style></style>',
        'type': 'text',
        'word_count': '1',
        'priority': '1',
        '_id': 'urn:localhost.abc',
        'state': 'published',
        'urgency': 2,
        'pubstatus': 'usable',
        'dateline': {
            'source': 'AAP',
            'text': 'Los Angeles, Aug 11 AAP -',
            'located': {
                'alt_name': '',
                'state': 'California',
                'city_code': 'Los Angeles',
                'city': 'Los Angeles',
                'dateline': 'city',
                'country_code': 'US',
                'country': 'USA',
                'tz': 'America/Los_Angeles',
                'state_code': 'CA'
            }
        },
        'creditline': 'sample creditline',
        'keywords': ['traffic'],
        'abstract': 'sample abstract',
        'place': [{'qcode': 'Australia', 'name': 'Australia',
                   'state': '', 'country': 'Australia',
                   'world_region': 'Oceania'}],
        'company_codes': [{'name': 'YANCOAL AUSTRALIA LIMITED', 'qcode': 'YAL', 'security_exchange': 'ASX'}],
    }

    dest = {'config': {'file_path': tempfile.gettempdir()}}
    subscriber = {'_id': 'foo', 'name': 'Foo', 'config': {}, 'destinations': [dest]}

    def get_article(self):
        article = self.article.copy()
        article['firstcreated'] = article['versioncreated'] = utcnow()
        return article

    def test_html_content(self):
        article = self.get_article()
        formatter = HTMLNewsMLG2Formatter()
        _, doc = formatter.format(article, self.subscriber)[0]
        self.assertIn('<body>', doc)
        self.assertIn('<b>HTML</b>', doc)

    def test_html_empty_content(self):
        article = self.get_article()
        article['body_html'] = ''
        formatter = HTMLNewsMLG2Formatter()
        _, doc = formatter.format(article, self.subscriber)[0]
        self.assertIn('<body>', doc)

    def test_featured_item_link(self):
        article = self.get_article()
        article['associations'] = {
            'featuremedia': {
                'type': 'picture',
                'renditions': {
                    'original': {
                        'mimetype': 'image/jpeg',
                        'media': 'featured'
                    }
                }
            }
        }

        formatter = HTMLNewsMLG2Formatter()
        with mock.patch('superdesk.app.media.get', return_value=io.BytesIO(b'test')):
            _, doc = formatter.format(article, self.subscriber)[0]
        self.assertIn('<link', doc)
        xml = etree.fromstring(doc.encode('utf-8'))
        link = xml.find(
            '{http://iptc.org/std/nar/2006-10-01/}itemSet/{http://iptc.org/std/nar/2006-10-01/}newsItem/' +
            '{http://iptc.org/std/nar/2006-10-01/}itemMeta/{http://iptc.org/std/nar/2006-10-01/}link')
        self.assertIsNotNone(link)
        self.assertEqual('image/jpeg', link.attrib['mimetype'])
        self.assertEqual('irel:seeAlso', link.attrib['rel'])
        self.assertIn('href', link.attrib)
        filepath = os.path.join(self.dest['config']['file_path'], link.attrib['href'])
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, 'rb') as related:
            self.assertEqual(b'test', related.read())

    def test_html_void(self):
        """Check that HTML void element use self closing tags, but other elements with no content use start/end pairs

        SDESK-947 regression test
        """
        article = self.get_article()
        article['body_html'] = ('<p><h1>The story body</h1><h3/>empty element on purpose<br/><strong>test</strong>'
                                '<em/><br/>other test</p>')
        formatter = HTMLNewsMLG2Formatter()
        _, doc = formatter.format(article, self.subscriber)[0]
        html_start = '<inlineXML contenttype="application/xhtml+xml">'
        html = doc[doc.find(html_start) + len(html_start):doc.find('</inlineXML>')]
        expected = ('<html><body><p></p><h1>The story body</h1><h3></h3>empty element on purpose<br/>'
                    '<strong>test</strong><em></em><br/>other test</body></html>')
        self.assertEqual(html, expected)
