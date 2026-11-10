<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:cdf="http://checklists.nist.gov/xccdf/1.2" exclude-result-prefixes="cdf">
<xsl:param name="assessment-uri" select="''"/>
<xsl:param name="assessment-phase" select="''"/>
<xsl:template name="evidence-assessment">
  <xsl:param name="item"/><xsl:param name="testresult"/><xsl:param name="result"/>
  <xsl:if test="$assessment-uri != ''">
    <xsl:variable name="a" select="document($assessment-uri)/assessment[@schema='1.0']"/>
    <xsl:variable name="p" select="$a/phase[@name=$assessment-phase]"/>
    <xsl:variable name="r" select="$p/rule[@id=$item/@id]"/>
    <div class="evidence-assessment panel panel-info">
      <div class="panel-heading"><h4 class="panel-title">Evidence assessment</h4></div>
      <div class="panel-body">
        <xsl:choose>
          <xsl:when test="count($p)!=1 or count($r)!=1 or not($assessment-phase='pre' or $assessment-phase='post' or $assessment-phase='followup')">
            <p>Indeterminate: no unique assessment for this phase and rule.</p>
          </xsl:when>
          <xsl:when test="not($p/test_result_id=$testresult/@id) or not(string($p/start_time)) or not(string($p/end_time)) or not($p/start_time=$testresult/@start-time) or not($p/end_time=$testresult/@end-time) or count($p/target)!=1 or count($testresult/cdf:target)!=1 or not($p/target=$testresult/cdf:target) or count($p/profile)!=1 or count($testresult/cdf:profile)!=1 or not($p/profile=$testresult/cdf:profile/@idref) or not($r/@status=$result)">
            <p>Indeterminate: assessment metadata or rule result does not match this report. Check phase and input selection.</p>
          </xsl:when>
          <xsl:otherwise>
            <p>Condition: <strong><xsl:value-of select="$assessment-phase"/></strong>. Saved rule result: <strong><xsl:value-of select="$r/@status"/></strong>.</p>
            <xsl:choose>
              <xsl:when test="$assessment-phase='pre'"><p>Baseline observation; no preceding condition is assessed.</p></xsl:when>
              <xsl:otherwise>
                <xsl:variable name="c" select="$a/comparison[@to=$assessment-phase and @rule_id=$item/@id and ((@from='pre' and @to='post') or (@from='post' and @to='followup'))]"/>
                <xsl:choose><xsl:when test="count($c)=1"><p>Scan transition: <xsl:value-of select="$c/@from"/> → <xsl:value-of select="$c/@to"/>: <strong><xsl:value-of select="$c"/></strong> (<xsl:value-of select="$c/@assessment"/>).</p></xsl:when><xsl:otherwise><p>Indeterminate: no unique preceding comparison.</p></xsl:otherwise></xsl:choose>
              </xsl:otherwise>
            </xsl:choose>
            <xsl:if test="string($r/reason)"><p><xsl:value-of select="$r/reason"/></p></xsl:if>
            <xsl:choose>
              <xsl:when test="$item/@id='xccdf_org.ssgproject.content_rule_sshd_disable_root_login'">
                <p>Scan/configuration consistency: <strong><xsl:value-of select="$p/consistency/@status"/></strong>. <xsl:value-of select="$p/consistency"/></p>
                <ul><xsl:for-each select="$p/setting"><li><code><xsl:value-of select="@name"/></code>: <xsl:choose><xsl:when test="@status='observed' and string(value)"><xsl:value-of select="value"/></xsl:when><xsl:otherwise>indeterminate — <xsl:value-of select="reason"/></xsl:otherwise></xsl:choose></li></xsl:for-each></ul>
                <xsl:if test="$p/capture-note"><p><xsl:value-of select="$p/capture-note"/></p></xsl:if>
              </xsl:when>
              <xsl:otherwise><p>File mode, ownership and read/write capability are not supplied by this assessment. A permissions result alone does not establish unauthorized write access.</p></xsl:otherwise>
            </xsl:choose>
            <h5>Evidence references</h5><ul><xsl:for-each select="$p/source[@kind='scan' or (@kind='effective_ssh' and $item/@id='xccdf_org.ssgproject.content_rule_sshd_disable_root_login')]"><li><xsl:choose><xsl:when test="starts-with(@href,'file:///')"><a href="{@href}"><xsl:value-of select="path"/></a></xsl:when><xsl:otherwise><xsl:value-of select="path"/></xsl:otherwise></xsl:choose><br/>SHA-256: <code><xsl:value-of select="sha256"/></code></li></xsl:for-each></ul>
            <h5>Limitations</h5><ul><xsl:for-each select="$a/limitation"><li><xsl:value-of select="."/></li></xsl:for-each></ul>
          </xsl:otherwise>
        </xsl:choose>
      </div>
    </div>
  </xsl:if>
</xsl:template>
</xsl:stylesheet>
