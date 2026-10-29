# Optional report enrichment: first implementation

Based on cwiggins0217/openscap main at c84c8aa. This prototype adds curated
security context to each finding using a local XML sidecar. It preserves the
original scan results, scoring, and existing OVAL details.

## Quick demonstration (no C build required)

From the repository root, with Python 3 and lxml installed:

```sh
python3 examples/report-enrichment/render_demo.py
python3 tests/API/XCCDF/report/test_enrichment.py
```

Open `enrichment-demo.html` and expand the first rule's details. The fixture
is synthetic: the text is illustrative and makes no ATT&CK or CVE claims.
The second rule demonstrates the explicit unmapped state.

The Python demo is ONLY a renderer demonstration for the repository's XCCDF
1.2 fixture. Use OpenSCAP's native command for your real scans, including its
namespace normalization and ARF handling.

## Native integration

Build and install this modified fork using `docs/developer/developer.adoc`.
Use an isolated development VM or installation prefix. Then use the modified
binary and its matching installed stylesheets:

```sh
oscap xccdf generate report \
  --enrichment examples/report-enrichment/context.xml \
  --output enriched-report.html \
  tests/API/XCCDF/report/results-xccdf12.xml
```

`--enrichment` is NEW in this patch. A stock oscap binary will not recognize it.
It is supported only by `xccdf generate report`, not `xccdf eval --report`.
Omitting it retains the normal report. Existing report generation accepts ARF,
but this prototype's executed tests cover XCCDF 1.2 only; test your real ARF
before relying on it.

Supply a trusted local XML file. The native CLI resolves its absolute path.
Paths containing apostrophes are rejected because this OpenSCAP version wraps
XSLT parameters in single-quoted XPath expressions. For this prototype, use
simple filenames without URI-special characters such as `#` or `%`.

## Mapping format

See `context.xml`. The namespace is `urn:openscap:report-enrichment:1` and
`schema-version` must be `1`. Match the Benchmark's exact ID and version,
then the Rule's exact ID. Do not change your real results to match the sample.
Copy those identifiers from your own results into a new mapping file.

Rule fields:

- `review-status` attribute: label such as `draft` or `reviewed`.
- `explanation`: why the configuration matters.
- Zero or more `attack` elements: attributes `technique` and `relationship`;
  child elements `justification`, `conditions`, and `source href="https://..."`.
- Zero or more `limitation` elements.
- `verification`: administrator guidance, not executed commands or observations.

All displayed content is escaped as text. Only HTTPS source URLs become links.
Duplicate matches fail rather than displaying competing interpretations.
Unsupported schema versions fail when context is rendered. An unmatched
benchmark version or rule produces an explicit 'No matching context' message.
This is minimal format checking, not full XML-schema validation.

## What this does not implement yet

- Automatic ATT&CK mappings or reviewed Ubuntu mapping coverage.
- CVE matching or a claim that a configuration failure is exploitable.
- Additional host evidence collection or joining vulnerability results.
- New risk scores, feed updates, or remote downloads.

Existing OVAL details remain the source of scan evidence. Keep curated mappings
separate from observations. A later evidence join should bind the original
input digest, asset, TestResult, rule, and result instance; a rule ID alone is
not enough for host-specific evidence.

## Changed code

- `utils/oscap-tool.h`: stores the optional CLI argument.
- `utils/oscap-xccdf.c`: parses and passes the local file to XSLT.
- `xsl/xccdf-report-impl.xsl`: calls the new template inside rule details.
- `xsl/xccdf-report-enrichment.xsl`: matches mappings and renders context.

`xsl/CMakeLists.txt` already installs `*.xsl`, so a newly configured build
includes the added stylesheet automatically.

## Validation performed

Eight lxml/libxslt renderer tests pass: optional behavior, mapped/unmapped
rules, version mismatch, benchmark mismatch, duplicate rejection, unsupported
schema rejection, text/link safety, and preservation of original rendered
content after removing the added sections. Each render also checks that the
input XML is unchanged. The synthetic demo renders successfully.

The native C changes have NOT been compiled or tested end to end here because
CMake and the OpenSCAP development dependencies are unavailable. A native
build and a real Ubuntu ARF test are the next validation gates.

## Next research step

Select one actual Ubuntu rule, capture its exact Benchmark ID/version and
Rule ID, and write a cited explanation and reviewed ATT&CK relationship.
Regenerate the report from the same saved scan. Only after that works should
you add Canonical vulnerability results and scan-specific evidence joins.
