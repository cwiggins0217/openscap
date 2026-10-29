#!/usr/bin/env python3
"""Standalone renderer regression tests: python3 test_enrichment.py (requires lxml)."""
import copy
from pathlib import Path
import tempfile
import unittest
from lxml import etree, html

ROOT = Path(__file__).resolve().parents[4]
NS = {'e': 'urn:openscap:report-enrichment:1'}
CDF = {'c': 'http://checklists.nist.gov/xccdf/1.2'}

class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.source = etree.parse(str(Path(__file__).with_name('results-xccdf12.xml')))
        self.mapping = etree.parse(str(ROOT / 'examples/report-enrichment/context.xml'))
        self.transform = etree.XSLT(etree.parse(str(ROOT / 'xsl/xccdf-report.xsl')))
        self.before = etree.tostring(self.source)

    def render(self, mapping=None):
        with tempfile.TemporaryDirectory() as folder:
            params = {}
            if mapping is not None:
                path = Path(folder) / 'context.xml'
                mapping.write(str(path))
                params['enrichment-file'] = etree.XSLT.strparam(path.as_uri())
            result = self.transform(self.source, **params)
            self.assertEqual(self.before, etree.tostring(self.source))
            return html.fromstring(bytes(result))

    def test_optional(self):
        self.assertFalse(self.render().xpath('//*[@class="security-context panel panel-info"]'))

    def test_mapping_and_unmapped(self):
        doc = self.render(self.mapping)
        self.assertEqual(len(doc.xpath('//*[contains(@class,"security-context")]')), 2)
        self.assertIn('This sample demonstrates', doc.text_content())
        self.assertIn('No matching context', doc.text_content())

    def test_version_mismatch(self):
        self.mapping.find('e:benchmark', NS).set('version', '2.0')
        self.assertNotIn('This sample demonstrates', self.render(self.mapping).text_content())

    def test_benchmark_mismatch(self):
        self.mapping.find('e:benchmark', NS).set('id', 'other')
        self.assertNotIn('This sample demonstrates', self.render(self.mapping).text_content())

    def test_duplicate_rejected(self):
        benchmark = self.mapping.find('e:benchmark', NS)
        benchmark.append(copy.deepcopy(benchmark[0]))
        with self.assertRaises(etree.XSLTApplyError):
            self.render(self.mapping)

    def test_bad_schema_rejected(self):
        self.mapping.getroot().set('schema-version', '2')
        with self.assertRaises(etree.XSLTApplyError):
            self.render(self.mapping)

    def test_text_and_links_safe(self):
        rule = self.mapping.find('e:benchmark/e:rule', NS)
        rule.find('e:explanation', NS).text = '<script>alert(1)</script>'
        attack = etree.SubElement(rule, '{%s}attack' % NS['e'], technique='TEST')
        etree.SubElement(attack, '{%s}source' % NS['e'], href='javascript:alert(1)')
        doc = self.render(self.mapping)
        self.assertIn('<script>alert(1)</script>', doc.text_content())
        self.assertFalse(doc.xpath('//script[text()="alert(1)"]'))
        self.assertFalse(doc.xpath('//a[starts-with(@href,"javascript:")]'))

    def test_existing_report_preserved(self):
        plain = self.render()
        enriched = self.render(self.mapping)
        for node in enriched.xpath('//*[contains(@class,"security-context")]'):
            node.getparent().remove(node)
        self.assertEqual(etree.tostring(plain), etree.tostring(enriched))

if __name__ == '__main__':
    unittest.main()
