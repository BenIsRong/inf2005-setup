# CVE Lab — Reading List

Curated references for the three CVEs in the lab, for understanding both the
**vulnerabilities** and their **mitigations**. Organised per CVE as:

1. **Primary sources** — the official advisory, CVE record, and the actual patch/commit.
2. **Weakness background** — the CWE class and foundational material on *why* this
   kind of bug happens and how it's defended against.

> Reading the **patch commits** alongside the advisories is the single most useful
> exercise: they show the exact lines that were broken and how the fix works. Those
> are the best defensive, no-exploit-code artifacts for the write-up.

---

## CVE-2026-93546 — Apache HTTP Server `mod_dav_fs` integer overflow

**Summary:** An integer overflow (CWE-190) in the `mod_dav_fs` module lets an
*authenticated* WebDAV client with write access crash Apache worker processes and
persistently corrupt a directory's property database, via PROPPATCH requests that
declare a very large number of XML namespaces. Affected through 2.4.68; fixed in 2.4.69.
CVSS 8.8 (High).

### Primary sources
- **Apache official security advisory (httpd 2.4 vulnerabilities list):**
  https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-93546
- **The fix commit (read this for the mitigation):**
  https://github.com/apache/httpd/commit/fa8c354189597453b2c8b38e081efa9b723abd3c
- **NVD record:** https://nvd.nist.gov/vuln/detail/CVE-2026-93546
- **CVE.org record:** https://www.cve.org/CVERecord?id=CVE-2026-93546
- **Debian security tracker (version/fix status):**
  https://security-tracker.debian.org/tracker/CVE-2026-93546
- **SUSE advisory (alternative CVSS analysis — note the differing score):**
  https://www.suse.com/security/cve/CVE-2026-93546/

### Weakness background (integer overflow / memory safety)
- **CWE-190: Integer Overflow or Wraparound** — https://cwe.mitre.org/data/definitions/190.html
- **CWE-131: Incorrect Calculation of Buffer Size** (the usual consequence) —
  https://cwe.mitre.org/data/definitions/131.html
- **"Basic Integer Overflows"** — blexim, *Phrack* #60 (the classic introduction to
  the bug class): http://phrack.org/issues/60/10.html
- **OWASP — Integer Overflow:** https://owasp.org/www-community/vulnerabilities/Integer_overflow
- **RFC 4918 — HTTP Extensions for WebDAV** (what PROPPATCH and properties actually are;
  §9.2 covers PROPPATCH): https://www.rfc-editor.org/rfc/rfc4918
- **Apache `mod_dav_fs` module docs:** https://httpd.apache.org/docs/2.4/mod/mod_dav_fs.html

### Mitigation-focused reading
- Apache hardening / WebDAV access control: https://httpd.apache.org/docs/2.4/misc/security_tips.html
- `LimitXMLRequestBody` directive (caps the request-body size the overflow relies on):
  https://httpd.apache.org/docs/2.4/mod/core.html#limitxmlrequestbody

---

## CVE-2026-19553 — CPython `ssl.SSLContext.wrap_bio()` hostname-verification bypass

**Summary:** `wrap_bio()` didn't require a non-`None` `server_hostname` even when
`check_hostname` was set, so a missing parameter could cause hostname verification to be
*silently skipped* while appearing to succeed (CWE-297: Improper Validation of
Certificate with Host Mismatch). Affected < 3.10.22, < 3.11.17, < 3.12.15, < 3.13.16,
and 3.14/3.15 pre-fix. CVSS v4 ~7.6 (High). Notably, **the fix can be applied in your own
code without upgrading** — always pass a valid `server_hostname`.

### Primary sources
- **Python Software Foundation security announcement (oss-security post):**
  https://www.openwall.com/lists/oss-security/2026/09/30/16
- **GitHub issue (root-cause discussion):** https://github.com/python/cpython/issues/156793
- **The fix PR:** https://github.com/python/cpython/pull/158503
- **The main fix commit (read this for the mitigation):**
  https://github.com/python/cpython/commit/1697ea386c707142555d98a1263176bbbc014a96
  - 3.13 branch: https://github.com/python/cpython/commit/f4e43ba525187282f2011da0e6ffc0d2b08d8062
  - 3.14 branch: https://github.com/python/cpython/commit/966bf426d0b6c31c1b0a255ff14a17143a466ced
- **PSF advisory (OSV):** https://osv.dev/vulnerability/PSF-2026-44
- **NVD record:** https://nvd.nist.gov/vuln/detail/CVE-2026-19553
- **Debian tracker (full list of branch commits):**
  https://security-tracker.debian.org/tracker/CVE-2026-19553

### Weakness background (TLS identity verification)
- **CWE-297: Improper Validation of Certificate with Host Mismatch** —
  https://cwe.mitre.org/data/definitions/297.html
- **CWE-295: Improper Certificate Validation** — https://cwe.mitre.org/data/definitions/295.html
- **"The Most Dangerous Code in the World: Validating SSL Certificates in
  Non-Browser Software"** — Georgiev et al., *ACM CCS 2012*. The definitive paper on
  exactly this class of failure (apparent-but-broken cert validation):
  https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf
- **RFC 6125 — Representation and Verification of Application Service Identity**
  (what hostname verification is supposed to do):
  https://www.rfc-editor.org/rfc/rfc6125
- **Python `ssl` module docs** (`wrap_bio`, `check_hostname`, `server_hostname`):
  https://docs.python.org/3/library/ssl.html

### Mitigation-focused reading
- The advisory's own mitigation guidance (pass a non-empty `server_hostname`) — in the
  oss-security post above. Good discussion point: a *code-discipline* fix vs. a version upgrade.

---

## CVE-2026-44172 — MariaDB Connector/C `mysql_real_escape_string()` big5 SQL injection

**Summary:** In Connector/C (`libmariadb`) 3.3.18 and 3.4.8,
`mysql_real_escape_string()` mishandled multi-byte sequences in the **big5** charset, so
a crafted byte sequence could leave a quote unescaped and reopen SQL injection
(CWE-89) despite the escaping. **The bug is in the client library, not the server.**
Fixed in 3.3.19 and 3.4.9. (CVSS varies widely by source — v4 ~6.9 up to critical 9.x.)

### Primary sources
- **MariaDB GitHub Security Advisory (GHSA-pv9p-5w55-55jm):**
  https://github.com/MariaDB/server/security/advisories/GHSA-pv9p-5w55-55jm
- **MariaDB JIRA ticket (CONC-819):** https://jira.mariadb.org/browse/CONC-819
- **NVD record:** https://nvd.nist.gov/vuln/detail/CVE-2026-44172
- **CVE.org record:** https://www.cve.org/CVERecord?id=CVE-2026-44172
- **Red Hat advisory (downstream analysis):**
  https://access.redhat.com/security/cve/CVE-2026-44172
- **MariaDB Connector/C repo (compare v3.4.8 vs v3.4.9 for the fix diff):**
  https://github.com/mariadb-corporation/mariadb-connector-c
  > No public PoC was released for this CVE — a relevant point for the disclosure section.

### Weakness background (SQL injection + multi-byte charset escaping)
- **CWE-89: SQL Injection** — https://cwe.mitre.org/data/definitions/89.html
- **CWE-176: Improper Handling of Unicode Encoding** — https://cwe.mitre.org/data/definitions/176.html
- **OWASP — SQL Injection:** https://owasp.org/www-community/attacks/SQL_Injection
- **The classic big5/GBK escaping-bypass writeup** — Chris Shiflett,
  "addslashes() Versus mysql_real_escape_string()" (the original explanation of the
  multi-byte-charset escaping flaw this CVE re-instances):
  https://shiflett.org/blog/2006/addslashes-versus-mysql-real-escape-string

### Mitigation-focused reading (the important one)
- **OWASP SQL Injection Prevention Cheat Sheet** — parameterised queries as the primary
  defence; why escaping is the fragile fallback:
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **OWASP Query Parameterization Cheat Sheet:**
  https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- **PHP docs — Prepared Statements (mysqli):** https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php
- **PHP docs — `PDO::ATTR_EMULATE_PREPARES`** (why emulated prepares can re-introduce the
  escaping path — the key caveat for this CVE):
  https://www.php.net/manual/en/pdo.setattribute.php
- Use `utf8mb4` rather than big5 as a connection charset — background:
  https://dev.mysql.com/doc/refman/8.0/en/charset-unicode-utf8mb4.html

---

## Cross-cutting references (good for the intro / methodology section)

- **CVSS v3.1 / v4.0 specification** (how severity scores are built — useful since these
  three are scored inconsistently across sources):
  https://www.first.org/cvss/
- **CWE Top 25 Most Dangerous Software Weaknesses** (places all three bug classes in
  context): https://cwe.mitre.org/top25/
- **NIST National Vulnerability Database:** https://nvd.nist.gov/
- **FIRST EPSS** (exploit-prediction scoring, referenced in several of the advisories):
  https://www.first.org/epss/

---

## Suggested reading order for the team

1. Start with the **three CWE pages** (190, 297, 89) — 10 minutes each, gives the mental model.
2. Read each **official advisory** for the plain-language description.
3. Read each **patch commit/diff** — this is where the real understanding (and the
   defensible demo material) lives.
4. For depth, the two landmark papers/writeups: **Georgiev et al. (CCS 2012)** for the
   TLS one, and **Shiflett** for the big5 one.
5. Finish with the **OWASP cheat sheets** for the mitigation section.

*Note: links were verified against official advisories and trackers at the time of
writing. For live affected-version data, always cross-check the NVD/CVE.org record.*
