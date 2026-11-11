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
      <div class="panel-heading"><h4 class="panel-title">Reason for the OpenSCAP result — <xsl:value-of select="translate($result, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/></h4></div>
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
            <ul>
              <xsl:choose>
                <xsl:when test="$result!='pass' and $result!='fail'">
                  <li>OpenSCAP returned <code><xsl:value-of select="$result"/></code>. A pass/fail reason is unavailable.</li>
                </xsl:when>
                <xsl:when test="$root-login">
                  <li>The rule requires direct root SSH login to be disabled (<code>PermitRootLogin no</code>).
                    <a href="https://github.com/ComplianceAsCode/content/blob/v0.1.82/linux_os/guide/services/ssh/ssh_server/sshd_disable_root_login/rule.yml">SSG 0.1.82 rule</a>
                  </li>
                  <li><xsl:choose>
                    <xsl:when test="not($observed)">The cause is indeterminate because this phase has no unique effective setting.</xsl:when>
                    <xsl:when test="$p/consistency/@status!='consistent' or not($p/consistency/@status) or (($setting/value='no') != ($result='pass'))">The cause is indeterminate because the scan and configuration evidence require reconciliation.</xsl:when>
                    <xsl:when test="$result='pass'">The captured setting meets this requirement and supports the PASS result.</xsl:when>
                    <xsl:otherwise>The captured setting differs from the required value and supports the FAIL result.</xsl:otherwise>
                  </xsl:choose></li>
                </xsl:when>
                <xsl:when test="$permissions">
                  <li>The rule checks permissions on SSH configuration drop-in files.
                    <a href="https://github.com/ComplianceAsCode/content/blob/v0.1.82/linux_os/guide/services/ssh/file_permissions_sshd_drop_in_config/rule.yml">SSG 0.1.82 rule</a>
                  </li>
                  <li>The exact file and permission bits behind this result are unavailable in the assessment input. Inspect the check details above.</li>
                </xsl:when>
                <xsl:otherwise><li>Inspect the rule's check details above for the conditions behind this result.</li></xsl:otherwise>
              </xsl:choose>
            </ul>
            <h5>Assessment</h5>
            <p><strong>Rule ID: </strong><code><xsl:value-of select="$item/@id"/></code></p>
            <p><strong>Status: </strong><xsl:choose>
              <xsl:when test="$assessment-phase='pre'">Scanned for compliance before the experiment's remediation step.</xsl:when>
              <xsl:when test="$assessment-phase='post'">Scanned for compliance after the remediation step.</xsl:when>
              <xsl:otherwise>Follow-up compliance scan.</xsl:otherwise>
            </xsl:choose></p>
            <ul>
              <xsl:choose>
                <xsl:when test="$root-login and $observed">
                  <li>The effective configuration was <code>PermitRootLogin <xsl:value-of select="$setting/value"/></code>.
                    <a href="https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html#PermitRootLogin">OpenSSH setting reference</a>
                  </li>
                </xsl:when>
                <xsl:when test="$root-login"><li>The effective PermitRootLogin value was not captured for this phase.</li></xsl:when>
                <xsl:when test="$permissions"><li>The recorded scan result is <code><xsl:value-of select="$result"/></code>. Per-file modes and ownership were not captured in this assessment.</li></xsl:when>
                <xsl:otherwise><li>The recorded scan result is <code><xsl:value-of select="$result"/></code>.</li></xsl:otherwise>
              </xsl:choose>
            </ul>
            <h5>Summary</h5>
            <p><xsl:choose>
              <xsl:when test="$root-login and $observed and $p/consistency/@status='consistent' and $result='fail' and $setting/value!='no'">
                <xsl:if test="$setting/value='without-password' or $setting/value='prohibit-password'">The captured setting still permits key-based root login. </xsl:if>
                To meet the requirement, verify named administrator access, set <code>PermitRootLogin no</code>, validate with <code>sshd -t</code>, reload SSH, and rescan.
              </xsl:when>
              <xsl:when test="$root-login and $observed and $p/consistency/@status='consistent' and $result='pass' and $setting/value='no'">The captured configuration disables direct root SSH login and agrees with the passing scan. Use the saved login tests to verify administrator access.</xsl:when>
              <xsl:when test="$root-login">Check the effective configuration for this phase and any applicable Match blocks before explaining the verdict or choosing remediation.</xsl:when>
              <xsl:when test="$permissions and $result='fail'">Identify the affected files in the check details, apply the rule's 0600 remediation target, and rescan.</xsl:when>
              <xsl:when test="$permissions and $result='pass'">OpenSCAP reports that the permission check passed. Save per-file metadata to document the configuration behind the result.</xsl:when>
              <xsl:otherwise>Review the check details and capture the relevant configuration before choosing remediation.</xsl:otherwise>
            </xsl:choose></p>
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
