"""Markdown engagement reports.

Turns raw module output into something a reader can act on: an authorization
header, a findings table ordered by severity, then the supporting detail.

Findings here are observations, not confirmed vulnerabilities. Recon sees what a
service advertises about itself, which is a lead to verify — so severity tops out
at medium and every finding says what would confirm it.
"""

from __future__ import annotations

import datetime as _dt
import pathlib
import re

SEVERITY_ORDER = {"medium": 0, "low": 1, "informational": 2}

# Services that are worth a second look when they answer from outside.
NOTABLE_PORTS = {
    21: ("low", "FTP often runs unencrypted; credentials and data cross in cleartext."),
    23: ("medium", "Telnet is cleartext by design. Anything typed over it is readable on the wire."),
    139: ("low", "NetBIOS session service exposed."),
    445: ("low", "SMB exposed. Check whether null sessions or guest access are permitted."),
    1433: ("low", "MS-SQL reachable. Confirm it is not using default or blank credentials."),
    3306: ("low", "MySQL reachable. Confirm bind address and that remote root is disabled."),
    3389: ("low", "RDP exposed. Confirm NLA is required and lockout policy is set."),
    5432: ("low", "PostgreSQL reachable. Confirm pg_hba.conf is not permitting host all all."),
    5900: ("medium", "VNC exposed. Historically deployed with no password or a weak one."),
    6379: ("medium", "Redis exposed. Default builds have no authentication at all."),
    9200: ("medium", "Elasticsearch exposed. Default builds have no authentication."),
    11211: ("medium", "Memcached exposed. No authentication, and usable for UDP amplification."),
    27017: ("medium", "MongoDB exposed. Older defaults bind publicly with no authentication."),
    2375: ("medium", "Docker API exposed without TLS is equivalent to root on the host."),
}

HEADER_IMPACT = {
    "strict-transport-security": "Browsers may be downgraded to plaintext HTTP on a later visit.",
    "content-security-policy": "No declared restriction on where scripts may load from.",
    "x-frame-options": "The page may be framed by another origin.",
    "x-content-type-options": "Browsers may MIME-sniff responses into an executable type.",
    "referrer-policy": "Full URLs may leak to third-party origins in the Referer header.",
    "permissions-policy": "No declared restriction on browser feature access.",
}

VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+-]*)[/ ]v?(\d+\.\d+(?:\.\d+)?)")


def _f(severity, title, evidence, verify, module):
    return {"severity": severity, "title": title, "evidence": evidence,
            "verify": verify, "module": module}


def derive_findings(results):
    """Read module output and produce ordered observations."""
    out = []

    ports = results.get("ports") or {}
    for entry in ports.get("open", []):
        port, service = entry["port"], entry.get("service", "unknown")
        if port in NOTABLE_PORTS:
            sev, why = NOTABLE_PORTS[port]
            out.append(_f(sev, f"{service} reachable on {port}/tcp", why,
                          "Connect and confirm whether authentication is actually required.",
                          "ports"))
        banner = entry.get("banner", "")
        for name, version in VERSION_RE.findall(banner or ""):
            if len(name) > 2:
                out.append(_f("informational", f"{name} {version} advertised on {port}/tcp",
                              f"Banner: {banner.splitlines()[0][:120]}",
                              f"Check {name} {version} against a CVE database before treating it as a finding.",
                              "ports"))
                break
        tls = entry.get("tls")
        if tls and tls.get("not_after"):
            try:
                expiry = _dt.datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y %Z")
                days = (expiry - _dt.datetime.now()).days
                if days < 0:
                    out.append(_f("medium", f"TLS certificate expired on {port}/tcp",
                                  f"Expired {abs(days)} days ago ({tls['not_after']}).",
                                  "Confirm in a browser; an expired cert trains users to click through warnings.",
                                  "ports"))
                elif days < 30:
                    out.append(_f("low", f"TLS certificate expires in {days} days on {port}/tcp",
                                  f"Not after: {tls['not_after']}.",
                                  "Confirm the renewal process is automated.", "ports"))
            except (ValueError, TypeError):
                pass

    http = (results.get("http") or {}).get("results", {})
    for scheme, res in http.items():
        if not res.get("reachable"):
            continue
        sec = res.get("security", {})
        missing = sec.get("missing", [])
        if missing:
            out.append(_f("low", f"Security headers absent on {scheme}",
                          "Missing: " + ", ".join(missing) + ". "
                          + " ".join(HEADER_IMPACT.get(m, "") for m in missing[:3]),
                          "Reproduce with curl -I and confirm no upstream proxy adds them.",
                          "http"))
        leaks = sec.get("version_disclosure", {})
        if leaks:
            out.append(_f("informational", f"Software versions disclosed in {scheme} headers",
                          "; ".join(f"{k}: {v}" for k, v in leaks.items()),
                          "Versions narrow an attacker's search. Confirm whether they can be suppressed.",
                          "http"))
        if sec.get("cookies_without_flags"):
            out.append(_f("low", f"Cookies set without Secure and HttpOnly on {scheme}",
                          f"{len(sec['cookies_without_flags'])} cookie(s) missing one or both flags.",
                          "Confirm which cookies carry session state.", "http"))

    robots = results.get("robots") or {}
    rob = (robots.get("found") or {}).get("/robots.txt")
    if rob and rob.get("notable"):
        out.append(_f("informational", "robots.txt names sensitive-looking paths",
                      "Disallowed: " + ", ".join(rob["notable"][:12]),
                      "robots.txt is a hint, not access control. Request each path and record the response code.",
                      "robots"))

    subs = results.get("subdomains") or {}
    if subs.get("found"):
        names = [s["name"] for s in subs["found"]]
        interesting = [n for n in names
                       if re.search(r"(dev|test|stag|uat|admin|internal|vpn|git|jenkins|backup)", n, re.I)]
        if interesting:
            out.append(_f("low", "Non-production hostnames resolve publicly",
                          ", ".join(interesting[:10]),
                          "Confirm whether these are reachable and whether they are in scope.",
                          "subdomains"))
        out.append(_f("informational", f"{len(names)} subdomain(s) resolve",
                      ", ".join(names[:20]) + ("…" if len(names) > 20 else ""),
                      "Each is a separate host with its own attack surface.", "subdomains"))

    tech = results.get("tech") or {}
    if tech.get("reachable"):
        stack = list(tech.get("from_headers", {}).values()) + tech.get("from_body", [])
        if tech.get("generator"):
            out.append(_f("informational", "Generator meta tag discloses the platform",
                          tech["generator"],
                          "Confirm the version and whether it is current.", "tech"))
        if stack:
            out.append(_f("informational", "Technology stack fingerprinted",
                          ", ".join(dict.fromkeys(stack)),
                          "Signature match only. Verify before relying on it.", "tech"))

    out.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return out


def _fmt_dns(d):
    lines = [f"Resolver backend: `{d.get('backend')}`", ""]
    for rt, vals in sorted((d.get("records") or {}).items()):
        lines.append(f"- **{rt}** — " + ", ".join(f"`{v}`" for v in vals))
    for addr, name in sorted((d.get("reverse") or {}).items()):
        lines.append(f"- **PTR** — `{addr}` resolves back to `{name}`")
    return lines or ["No records returned."]


def _fmt_ports(d):
    if d.get("error"):
        return [d["error"]]
    if not d.get("open"):
        return [f"No open ports among {d.get('ports_scanned', 0)} scanned."]
    lines = [f"Scanned `{d['scanned_host']}` — {len(d['open'])} open of {d['ports_scanned']}.", "",
             "| Port | Service | RTT | Banner |", "|---|---|---|---|"]
    for e in d["open"]:
        banner = (e.get("banner") or "").splitlines()
        banner = banner[0][:80].replace("|", "\\|") if banner else ""
        lines.append(f"| `{e['port']}/tcp` | {e.get('service','?')} | {e.get('rtt_ms','?')} ms | `{banner}` |")
    return lines


def _fmt_http(d):
    lines = []
    for scheme, res in (d.get("results") or {}).items():
        lines.append(f"**{scheme}** — " +
                     (f"HTTP {res['final_status']}" if res.get("reachable")
                      else f"unreachable ({res.get('error')})"))
        if not res.get("reachable"):
            lines.append("")
            continue
        if res.get("title"):
            lines.append(f"- Title: {res['title']}")
        if res.get("server"):
            lines.append(f"- Server: `{res['server']}`")
        chain = res.get("redirect_chain") or []
        if len(chain) > 1:
            lines.append("- Redirects: " + " → ".join(str(c["status"]) for c in chain))
        sec = res.get("security", {})
        if sec.get("present"):
            lines.append("- Present: " + ", ".join(f"`{k}`" for k in sec["present"]))
        if sec.get("missing"):
            lines.append("- Missing: " + ", ".join(f"`{k}`" for k in sec["missing"]))
        lines.append("")
    return lines


def _fmt_generic(d):
    lines = []
    for key, value in d.items():
        if key in ("target", "raw") or value in (None, [], {}, ""):
            continue
        if isinstance(value, (list, dict)) and len(str(value)) > 400:
            lines.append(f"- **{key}**: {len(value)} entries")
        else:
            lines.append(f"- **{key}**: {value}")
    return lines or ["No data."]


FORMATTERS = {"dns": _fmt_dns, "ports": _fmt_ports, "http": _fmt_http}


def build(record) -> str:
    """Render one scan record as a Markdown report."""
    results = record.get("results") or {}
    findings = derive_findings(results)
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("medium", "low", "informational")}

    md = [
        f"# Reconnaissance — {record.get('target')}",
        "",
        "## Authorization",
        "",
        f"- **Engagement:** {record.get('engagement') or '—'}",
        f"- **Authorized by:** {record.get('authorized_by') or '—'}",
        f"- **Authorization ref:** {record.get('authorization_ref') or '—'}",
        f"- **Scan completed:** {record.get('finished', '—')}",
        f"- **Modules run:** {', '.join(record.get('modules', []))}",
        "",
        "> Every target in this report passed the scope check before any packet was sent. "
        "Findings below are observations from what services advertise about themselves; "
        "each names what would be needed to confirm it.",
        "",
        "## Summary",
        "",
        f"{len(findings)} observation(s): "
        f"{counts['medium']} medium, {counts['low']} low, {counts['informational']} informational.",
        "",
    ]

    if findings:
        md += ["| # | Severity | Observation | Source |", "|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            md.append(f"| {i} | {f['severity'].title()} | {f['title']} | `{f['module']}` |")
        md += ["", "## Observations", ""]
        for i, f in enumerate(findings, 1):
            md += [
                f"### {i}. {f['title']}",
                "",
                f"**Severity:** {f['severity'].title()}  ",
                f"**Source module:** `{f['module']}`",
                "",
                f"**Evidence.** {f['evidence']}",
                "",
                f"**To confirm.** {f['verify']}",
                "",
            ]
    else:
        md += ["Nothing notable surfaced from the modules that ran.", ""]

    md += ["## Raw module output", ""]
    for name, data in results.items():
        md += [f"### {name}", ""]
        md += FORMATTERS.get(name, _fmt_generic)(data)
        md += [""]

    if record.get("failed"):
        md += ["### Modules that failed", ""]
        for name, err in record["failed"].items():
            md.append(f"- `{name}`: {err}")
        md.append("")

    md += ["---", "",
           f"Generated by `recon` from scan `{record.get('id','—')}`. "
           "Recon output is a starting point, not a vulnerability assessment."]
    return "\n".join(md)


def write(record, directory="reports") -> pathlib.Path:
    d = pathlib.Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(record.get("target", "target")))
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = d / f"{safe}-{stamp}.md"
    path.write_text(build(record), encoding="utf-8")
    return path
