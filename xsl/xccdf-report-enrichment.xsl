<?xml version="1.0" encoding="UTF-8"?>
<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:cdf="http://checklists.nist.gov/xccdf/1.2"
    xmlns:e="urn:openscap:report-enrichment:1"
    exclude-result-prefixes="cdf e">

<xsl:param name="enrichment-file" select="''"/>

<!-- Context is curated knowledge, never host observations or CVE detection. -->
<xsl:template name="security-context">
    <xsl:param name="item"/>
    <xsl:if test="string-length($enrichment-file) &gt; 0">
        <xsl:variable name="map" select="document($enrichment-file)/e:enrichment"/>
        <xsl:if test="not($map) or $map/@schema-version != '1' or not($map/@schema-version)">
            <xsl:message terminate="yes">Invalid enrichment document: expected schema-version 1 and enrichment namespace.</xsl:message>
        </xsl:if>
        <xsl:variable name="benchmark" select="$item/ancestor::cdf:Benchmark"/>
        <xsl:variable name="entry" select="$map/e:benchmark[@id=$benchmark/@id and @version=$benchmark/cdf:version]/e:rule[@id=$item/@id]"/>
        <xsl:if test="count($entry) &gt; 1">
            <xsl:message terminate="yes">Duplicate enrichment mapping for a benchmark version and rule.</xsl:message>
        </xsl:if>
        <div class="security-context panel panel-info">
            <div class="panel-heading"><h4 class="panel-title">Security context</h4></div>
            <div class="panel-body">
                <xsl:choose>
                    <xsl:when test="$entry">
                        <p class="text-muted">Curated context; this section does not establish exploitation or CVE applicability.</p>
                        <p><strong>Review status: </strong><xsl:value-of select="$entry/@review-status"/></p>
                        <p><xsl:value-of select="$entry/e:explanation"/></p>
                        <xsl:for-each select="$entry/e:attack">
                            <p><strong>ATT&amp;CK reference </strong><xsl:value-of select="@technique"/><xsl:text> </xsl:text>
                                <xsl:choose>
                                    <xsl:when test="starts-with(e:source/@href, 'https://')">
                                        <a href="{e:source/@href}" rel="noopener noreferrer"><xsl:value-of select="e:source/@href"/></a>
                                    </xsl:when>
                                    <xsl:otherwise><xsl:value-of select="e:source/@href"/></xsl:otherwise>
                                </xsl:choose>
                            </p>
                        </xsl:for-each>
                        <xsl:for-each select="$entry/e:limitation">
                            <p><strong>Limitation: </strong><xsl:value-of select="."/></p>
                        </xsl:for-each>
                        <xsl:if test="$entry/e:verification">
                            <p><strong>Verification guidance: </strong><xsl:value-of select="$entry/e:verification"/></p>
                        </xsl:if>
                    </xsl:when>
                    <xsl:otherwise><p>No matching context for this benchmark version and rule.</p></xsl:otherwise>
                </xsl:choose>
            </div>
        </div>
    </xsl:if>
</xsl:template>
</xsl:stylesheet>
