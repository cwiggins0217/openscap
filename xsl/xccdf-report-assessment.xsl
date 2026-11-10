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
      <div class="panel-heading"><h4 class="panel-title">OpenSCAP reported <xsl:value-of select="translate($result, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/></h4></div>
      <div class="panel-body">
        <xsl:choose>
          <xsl:when test="count($p)!=1 or count($r)!=1 or not($assessment-phase='pre' or $assessment-phase='post' or $assessment-phase='followup')">
            <p>Indeterminate: no unique assessment for this phase and rule.</p>
          </xsl:when>
          <xsl:when test="not($p/test_result_id=$testresult/@id) or not(string($p/start_time)) or not(string($p/end_time)) or not($p/start_time=$testresult/@start-time) or not($p/end_time=$testresult/@end-time) or count($p/target)!=1 or count($testresult/cdf:target)!=1 or not($p/target=$testresult/cdf:target) or count($p/profile)!=1 or count($testresult/cdf:profile)!=1 or not($p/profile=$testresult/cdf:profile/@idref) or not($r/@status=$result)">
            <p>Indeterminate: assessment metadata or rule result does not match this report. Check phase and input selection.</p>
          </xsl:when>
          <xsl:otherwise>
            <xsl:variable name="root-login" select="$item/@id='xccdf_org.ssgproject.content_rule_sshd_disable_root_login'"/>
            <xsl:variable name="permissions" select="$item/@id='xccdf_org.ssgproject.content_rule_file_permissions_sshd_drop_in_config'"/>
            <xsl:variable name="setting" select="$p/setting[@name='permitrootlogin']"/>
            <xsl:variable name="observed" select="count($setting)=1 and $setting/@status='observed' and count($setting/value)=1 and normalize-space($setting/value)!=''"/>
            <h5>Scan conditions</h5>
            <ul>
              <li>Host: <xsl:value-of select="$p/target"/></li>
              <li>Profile: <xsl:value-of select="$p/profile"/></li>
              <xsl:choose>
                <xsl:when test="$root-login"><li>Required setting: <code>PermitRootLogin no</code>.</li></xsl:when>
                <xsl:when test="$permissions"><li>SSH server drop-in files must meet the benchmark's file permission requirement.</li></xsl:when>
              </xsl:choose>
            </ul>
            <h5>Assessment</h5>
            <p><strong>Rule ID: </strong><code><xsl:value-of select="$item/@id"/></code></p>
            <p><strong>Status: </strong><xsl:choose>
              <xsl:when test="$assessment-phase='pre'">Baseline scan before the experiment's hardening step.</xsl:when>
              <xsl:when test="$assessment-phase='post'">First scan after the hardening step.</xsl:when>
              <xsl:otherwise>Follow-up scan.</xsl:otherwise>
            </xsl:choose></p>
            <p><strong>Observed condition: </strong><xsl:choose>
              <xsl:when test="$root-login and $observed">The saved SSH configuration shows <code>PermitRootLogin <xsl:value-of select="$setting/value"/></code>.</xsl:when>
              <xsl:when test="$root-login">Indeterminate. No unique effective PermitRootLogin value was recorded for this scan.</xsl:when>
              <xsl:when test="$permissions">The scan records the rule result. The assessment has no per-file mode or ownership evidence.</xsl:when>
              <xsl:otherwise>No rule-specific observation is available.</xsl:otherwise>
            </xsl:choose></p>
            <xsl:if test="$root-login and $p/consistency">
              <p><strong>Evidence check: </strong><xsl:value-of select="$p/consistency/@status"/>. <xsl:value-of select="$p/consistency"/></p>
            </xsl:if>
            <xsl:for-each select="$item/cdf:reference[(contains(@href,'nist.gov/') or contains(@href,'cisecurity.org/')) and (starts-with(@href,'http://') or starts-with(@href,'https://')) and normalize-space(.)]">
              <p><strong>Benchmark reference: </strong><a href="{@href}"><xsl:call-template name="convert-reference-url-to-name"><xsl:with-param name="href" select="@href"/></xsl:call-template><xsl:text> </xsl:text><xsl:value-of select="."/></a></p>
            </xsl:for-each>
            <h5>Summary</h5>
            <xsl:choose>
              <xsl:when test="$root-login">
                <p><xsl:choose>
                  <xsl:when test="$result!='fail' and $result!='pass'">This scan did not return a pass or fail verdict.</xsl:when>
                  <xsl:when test="not($observed)">The effective setting cannot explain this verdict without a capture from the same phase.</xsl:when>
                  <xsl:when test="$p/consistency/@status!='consistent' or not($p/consistency/@status) or (($setting/value='no') != ($result='pass'))">The cause is indeterminate. Check capture timing and the applicable SSH Match context.</xsl:when>
                  <xsl:when test="$result='pass'">The captured value matches the requirement to disable direct root login.</xsl:when>
                  <xsl:when test="$setting/value='without-password' or $setting/value='prohibit-password'">The captured value blocks password authentication for root but still permits key-based root login. The rule requires all direct root SSH logins to be disabled.</xsl:when>
                  <xsl:otherwise>The captured value differs from the required value of <code>no</code>.</xsl:otherwise>
                </xsl:choose></p>
                <p>Disabling direct root login directs administrators through individual accounts.
                  <xsl:if test="$result='fail'"> Verify named administrator access, set <code>PermitRootLogin no</code>, validate with <code>sshd -t</code>, reload SSH, and repeat the scan.</xsl:if>
                </p>
              </xsl:when>
              <xsl:when test="$permissions">
                <p>Restricting drop-in file permissions protects SSH policy.
                  <xsl:if test="$result='fail'"> Inspect the drop-in files, correct the modes identified by the benchmark check, and repeat the scan.</xsl:if>
                </p>
              </xsl:when>
              <xsl:otherwise><p>Review the rule definition and its check output to interpret this result.</p></xsl:otherwise>
            </xsl:choose>
            <xsl:if test="$assessment-phase!='pre'">
              <xsl:variable name="c" select="$a/comparison[@to=$assessment-phase and @rule_id=$item/@id and ((@from='pre' and @to='post') or (@from='post' and @to='followup'))]"/>
              <xsl:choose>
                <xsl:when test="count($c)=1"><p>Change since the preceding scan: <strong><xsl:value-of select="$c"/></strong> (<xsl:value-of select="$c/@assessment"/>).</p></xsl:when>
                <xsl:otherwise><p>Indeterminate: no unique preceding comparison.</p></xsl:otherwise>
              </xsl:choose>
            </xsl:if>
            <xsl:if test="string($r/reason)"><p><xsl:value-of select="$r/reason"/></p></xsl:if>
            <details><summary>Supporting evidence and limitations</summary>
            <xsl:if test="$root-login">
              <ul><xsl:for-each select="$p/setting"><li><code><xsl:value-of select="@name"/></code>: <xsl:choose><xsl:when test="@status='observed' and string(value)"><xsl:value-of select="value"/></xsl:when><xsl:otherwise>indeterminate — <xsl:value-of select="reason"/></xsl:otherwise></xsl:choose></li></xsl:for-each></ul>
              <xsl:if test="$p/capture-note"><p><xsl:value-of select="$p/capture-note"/></p></xsl:if>
            </xsl:if>
            <h5>Evidence references</h5><ul><xsl:for-each select="$p/source[@kind='scan' or (@kind='effective_ssh' and $item/@id='xccdf_org.ssgproject.content_rule_sshd_disable_root_login')]"><li><xsl:choose><xsl:when test="starts-with(@href,'file:///')"><a href="{@href}"><xsl:value-of select="path"/></a></xsl:when><xsl:otherwise><xsl:value-of select="path"/></xsl:otherwise></xsl:choose><br/>SHA-256: <code><xsl:value-of select="sha256"/></code></li></xsl:for-each></ul>
            <h5>Limitations</h5><ul><xsl:for-each select="$a/limitation"><li><xsl:value-of select="."/></li></xsl:for-each></ul>
            </details>
          </xsl:otherwise>
        </xsl:choose>
      </div>
    </div>
  </xsl:if>
</xsl:template>
</xsl:stylesheet>
