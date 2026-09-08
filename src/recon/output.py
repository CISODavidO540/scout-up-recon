"""Console and file rendering for scan results."""

from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import sys

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(t):
    return _c("1", t)


def dim(t):
    return _c("2", t)


def green(t):
    return _c("32", t)


def yellow(t):
    return _c("33", t)


def red(t):
    return _c("31", t)


def rule(title=""):
    width = 72
    if not title:
        return dim("-" * width)
    return dim("-- ") + bold(title) + dim(" " + "-" * max(0, width - len(title) - 4))


def render_dns(data):
    lines = [rule(f"DNS  {data['target']}"), dim(f"   backend: {data['backend']}")]
    if not data["records"]:
        lines.append(yellow("   no records returned"))
    for rtype, values in sorted(data["records"].items()):
        for v in values:
            lines.append(f"   {rtype:<6} {v}")
    for addr, name in sorted(data.get("reverse", {}).items()):
        lines.append(dim(f"   PTR    {addr} -> {name}"))
    return lines


def render_whois(data):
    lines = [rule(f"WHOIS  {data['target']}")]
    if not data.get("available"):
        return lines + [yellow(f"   {data.get('note', 'unavailable')}")]
    if data.get("error"):
        return lines + [red(f"   {data['error']}")]
    summary = data.get("summary", {})
    if not summary:
        return lines + [yellow("   no fields parsed (registry format may differ)")]
    for key, value in summary.items():
        if isinstance(value, list):
            lines.append(f"   {key:<13} {', '.join(value)}")
        else:
            lines.append(f"   {key:<13} {value}")
    return lines


def render_subdomains(data):
    lines = [rule(f"SUBDOMAINS  {data['target']}")]
    if data.get("error"):
        return lines + [red(f"   {data['error']}")]
    if data.get("wildcard_detected"):
        lines.append(yellow(
            f"   wildcard DNS detected ({', '.join(data['wildcard_detected'])}) "
            "— results filtered against it"))
    found = data.get("found", [])
    lines.append(dim(f"   {len(found)} found from {data['words_tried']} candidates"))
    for entry in found:
        lines.append(f"   {green(entry['name']):<44} {', '.join(entry['addresses'])}")
    for skip in data.get("skipped_out_of_scope", []):
        lines.append(yellow(f"   [out of scope, not probed] {skip['name']}"))
    return lines


def render_ports(data):
    lines = [rule(f"PORTS  {data['target']}  ({data['scanned_host']})")]
    if data.get("error"):
        return lines + [red(f"   {data['error']}")]
    lines.append(dim(f"   {data['ports_scanned']} scanned, {len(data['open'])} open"))
    if not data["open"]:
        lines.append(yellow("   no open ports found"))
    for entry in data["open"]:
        head = f"   {green(str(entry['port']) + '/tcp'):<16} {entry['service']:<16} {entry['rtt_ms']} ms"
        lines.append(head)
        if entry.get("banner"):
            lines.append(dim(f"       banner: {entry['banner'].splitlines()[0][:100]}"))
        if entry.get("tls"):
            t = entry["tls"]
            subj = (t.get("subject") or {}).get("commonName", "?")
            lines.append(dim(f"       tls: {t['tls_version']} {t['cipher']}  CN={subj}  expires {t['not_after']}"))
    counts = ", ".join(f"{v} {k}" for k, v in data["summary"].items() if v)
    if counts:
        lines.append(dim(f"   ({counts})"))
    return lines


def render_http(data):
    lines = [rule(f"HTTP  {data['target']}")]
    for scheme, res in data["results"].items():
        if not res.get("reachable"):
            lines.append(yellow(f"   {scheme}: unreachable — {res.get('error')}"))
            continue
        lines.append(f"   {bold(scheme)}: {res['final_status']}  {res.get('title') or ''}")
        if res.get("server"):
            lines.append(dim(f"       server: {res['server']}"))
        chain = res.get("redirect_chain", [])
        if len(chain) > 1:
            lines.append(dim("       redirects: " + " -> ".join(str(c['status']) for c in chain)))
        sec = res["security"]
        if sec["missing"]:
            lines.append(yellow(f"       missing: {', '.join(sec['missing'])}"))
        if sec["version_disclosure"]:
            disclosed = ", ".join(f"{k}={v}" for k, v in sec["version_disclosure"].items())
            lines.append(yellow(f"       discloses: {disclosed}"))
    return lines


def render_traceroute(data):
    lines = [rule(f"TRACEROUTE  {data['target']}")]
    if not data.get("available"):
        return lines + [yellow(f"   {data.get('note', 'unavailable')}")]
    if data.get("error"):
        return lines + [red(f"   {data['error']}")]
    hops = data.get("hops", [])
    if not hops:
        return lines + [yellow("   no hops parsed")]
    lines.append(dim(f"   via {data['binary']} to {data['scanned_host']}"))
    for hop in hops:
        n = f"{hop['hop']:>3}"
        if hop["responded"]:
            lines.append(f"   {n}  {hop['detail']}")
        else:
            lines.append(dim(f"   {n}  *"))
    silent = data.get("silent_hops", 0)
    tail = f"   {len(hops)} hops"
    if silent:
        tail += f", {silent} silent"
    lines.append(dim(tail))
    return lines


def render_tech(data):
    lines = [rule(f"TECH  {data['target']}")]
    if not data.get("reachable"):
        return lines + [yellow(f"   unreachable — {data.get('error', 'no response')}")]
    lines.append(dim(f"   {data['status']}  {data['url']}"))
    for label, value in (data.get("from_headers") or {}).items():
        lines.append(f"   {label:<20} {value}")
    for sig in data.get("from_body") or []:
        lines.append(f"   {'page markup':<20} {sig}")
    if data.get("generator"):
        lines.append(f"   {'generator':<20} {data['generator']}")
    if data.get("cookie_names"):
        lines.append(dim(f"   cookies: {', '.join(data['cookie_names'])}"))
    if not any((data.get("from_headers"), data.get("from_body"),
                data.get("generator"), data.get("cookie_names"))):
        lines.append(yellow("   nothing fingerprinted"))
    return lines


def render_robots(data):
    lines = [rule(f"ROBOTS  {data['target']}")]
    if data.get("error"):
        return lines + [red(f"   {data['error']}")]
    found = data.get("found") or {}
    if not found:
        lines.append(yellow("   none of the standard files are published"))
    for path, info in found.items():
        detail = info if isinstance(info, str) else ""
        lines.append(f"   {green('found'):<16} {path}")
        for entry in (info.get("interesting", []) if isinstance(info, dict) else []):
            lines.append(yellow(f"       flagged: {entry}"))
        if detail:
            lines.append(dim(f"       {detail[:120]}"))
    missing = data.get("missing") or []
    if missing:
        lines.append(dim(f"   absent: {', '.join(missing)}"))
    return lines


RENDERERS = {
    "dns": render_dns,
    "whois": render_whois,
    "subdomains": render_subdomains,
    "ports": render_ports,
    "http": render_http,
    "traceroute": render_traceroute,
    "tech": render_tech,
    "robots": render_robots,
}


def render(module, data):
    fn = RENDERERS.get(module)
    if not fn:
        return [rule(module), json.dumps(data, indent=2, default=str)]
    return fn(data)


def write_json(results, meta, path):
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"meta": meta, "results": results}, indent=2, default=str))
    return p




def timestamp():
    return _dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
