# White Hat Agreement and Rules of Engagement

This document is the authorization record for any engagement run with this tool.
Fill one out, get it signed, and keep it **before** the first scan. The scope file
the tool reads is derived from Section 3 of this document, and it should never
contain a target that does not appear here.

An unsigned agreement means an unauthorized test. There is no informal version of
this step.

---

## 1. Parties

| Field | Value |
|---|---|
| Tester | |
| Organization or course | |
| Client or system owner | |
| Authorizing person (name and title) | |
| Authorizing person's contact | |
| Emergency contact during testing | |

The authorizing person must have the actual authority to permit testing of the
systems in Section 3. A system administrator who does not own the system cannot
grant this. For coursework, this is the instructor; for a lab environment, the
person who owns the lab.

## 2. Engagement window

| Field | Value |
|---|---|
| Start date and time | |
| End date and time | |
| Permitted testing hours | |
| Time zone | |

Testing outside this window is unauthorized, including finishing a scan that was
started inside it. The tool enforces the date range, but the permitted-hours
restriction is on you.

## 3. Scope

### 3.1 In scope

List every authorized target. Hostnames, IP addresses, and CIDR ranges.

| Target | Type | Notes |
|---|---|---|
| | | |

### 3.2 Explicitly out of scope

List anything inside a permitted range that must not be touched. Exclusions
override inclusions.

| Target | Reason |
|---|---|
| | | 

### 3.3 Third-party systems

Systems the target depends on but the client does not own — hosting providers,
CDNs, DNS providers, payment processors, SaaS platforms — are **out of scope by
default**. The client cannot authorize testing of a system they do not control.
Testing these requires separate written permission from that provider.

Note that scanning a hostname behind a CDN scans the CDN, not the client.

## 4. Permitted activities

Check what is authorized. Anything unchecked is prohibited.

- [ ] Passive reconnaissance (DNS, WHOIS, public records, certificate transparency)
- [ ] Subdomain enumeration by DNS resolution
- [ ] Network path tracing
- [ ] Port scanning and service identification
- [ ] Banner grabbing and version fingerprinting
- [ ] Web application fingerprinting and security-header review
- [ ] Retrieval of well-known files (`robots.txt`, `sitemap.xml`, `security.txt`)
- [ ] Vulnerability scanning with an automated scanner
- [ ] Manual verification of identified findings
- [ ] Exploitation of identified vulnerabilities
- [ ] Post-exploitation, privilege escalation, or lateral movement
- [ ] Social engineering, phishing, or pretexting
- [ ] Physical access testing

The modules in this tool cover the first seven items only. The tool cannot exploit
anything, and severity in its reports stops at medium for that reason.

## 5. Prohibited activities

These are prohibited in every engagement regardless of what Section 4 permits,
unless separately and specifically authorized in writing:

- Denial of service, resource exhaustion, or any test whose purpose is to degrade
  availability
- Modifying, deleting, or corrupting data
- Exfiltrating real customer, employee, or personal data. If proof is required,
  record the minimum necessary and note it rather than copying the data
- Installing persistence, backdoors, or any software that survives the engagement
- Password cracking against production accounts belonging to real people
- Testing outside the window or scope, including targets discovered during testing
- Sharing findings, scan output, or the scope file with anyone outside the
  authorized recipients in Section 7

## 6. Rules of engagement

**Handling accidental out-of-scope access.** Stop immediately, do not explore
further, record what happened and when, and notify the authorizing person the same
day. Do not attempt to quietly undo it.

**Handling discovery of an active compromise.** If evidence of a real intrusion by
someone else is found, stop testing and notify the emergency contact immediately.
Do not touch the evidence. The engagement may become an incident response.

**Handling discovery of illegal content.** Stop, do not copy or examine it, and
notify the authorizing person and legal counsel. Reporting obligations may apply.

**Handling a system going down.** Stop testing, notify the emergency contact,
document the last actions taken, and assist with restoration if asked.

**Rate limiting.** Keep scans within `max_concurrency` in the scope file. A connect
scan is loud; a fast one against fragile infrastructure can look like an attack or
cause an outage.

**Logging.** Keep a record of what was run and when. This tool writes one to
`out/scans/` automatically. If your activity is later confused with a real attack,
that log is what distinguishes you from an intruder.

## 7. Data handling and confidentiality

| Field | Value |
|---|---|
| Where findings will be stored | |
| Who may receive the report | |
| Required deletion date for scan data | |
| Encryption required at rest | Yes / No |

Scan output names live hosts and open services. It is a roadmap to the client's
weak points and must be handled as confidential material: not committed to a public
repository, not posted in a shared chat, not left on a shared lab machine after the
engagement ends.

Delete raw scan data by the date above. This tool caps its own history at 50
records, which is a convenience, not compliance.

## 8. Reporting

| Field | Value |
|---|---|
| Report due date | |
| Format required | |
| Findings requiring immediate notification | Critical / High / Other: |

Critical findings should be reported when found, not held for the final report.

## 9. Liability and authorization statement

The client authorizes the tester to perform the activities checked in Section 4
against the targets in Section 3 during the window in Section 2. The client
confirms they have the authority to grant this authorization, and that any required
notification of hosting providers or third parties has been completed.

The tester agrees to stay within scope, to stop when instructed, to protect all
data encountered, and to report findings only to the recipients named in Section 7.

## 10. Signatures

| Role | Name | Signature | Date |
|---|---|---|---|
| Tester | | | |
| Authorizing person | | | |

---

## Turning this into a scope file

Sections 2 and 3 map directly onto `config/scope.json`:

```json
{
  "engagement": "<Section 1: course or engagement name>",
  "authorized_by": "<Section 1: authorizing person>",
  "authorization_ref": "<where this signed agreement is filed>",
  "valid_from": "<Section 2: start date, YYYY-MM-DD>",
  "valid_until": "<Section 2: end date, YYYY-MM-DD>",
  "in_scope": ["<Section 3.1 targets>"],
  "out_of_scope": ["<Section 3.2 targets>"],
  "max_concurrency": 8,
  "strict_resolution": false
}
```

Verify it before scanning:

```bash
PYTHONPATH=src python3 -m recon <target> --check
```

That prints whether the target is authorized and what it resolves to, without
sending anything to it.

Keep the signed agreement. `config/scope.json` is gitignored and must stay that
way: it names real targets and a real person who authorized testing them.
