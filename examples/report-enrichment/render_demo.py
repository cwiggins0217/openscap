#!/usr/bin/env python3
"""Render the synthetic XCCDF 1.2 fixture without compiling OpenSCAP."""
from pathlib import Path
from lxml import etree

ROOT = Path(__file__).resolve().parents[2]
parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
source = etree.parse(str(ROOT / 'tests/API/XCCDF/report/results-xccdf12.xml'), parser)
transform = etree.XSLT(
    etree.parse(str(ROOT / 'xsl/xccdf-report.xsl'), parser),
    access_control=etree.XSLTAccessControl(read_file=True, read_network=False,
                                        write_file=False, write_network=False),
)
result = transform(source, **{
    'enrichment-file': etree.XSLT.strparam((Path(__file__).parent / 'context.xml').resolve().as_uri())
})
output = Path.cwd() / 'enrichment-demo.html'
output.write_bytes(bytes(result))
print(output)
