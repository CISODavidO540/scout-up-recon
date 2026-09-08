"""DNS record enumeration.

Uses dnspython when it is installed, otherwise shells out to `dig`, otherwise
falls back to stdlib address lookups only. The fallback chain matters on lab
machines where you cannot install packages.
"""

from __future__ import annotations

import shutil
import socket
import subprocess

NAME = "dns"
DESCRIPTION = "Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)"

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def _via_dnspython(host, rtypes, timeout):
    import dns.resolver  # optional dependency

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    out = {}
    for rt in rtypes:
        try:
            answers = resolver.resolve(host, rt)
            out[rt] = sorted(r.to_text().strip('"') for r in answers)
        except Exception:
            continue
    return out


def _via_dig(host, rtypes, timeout):
    out = {}
    for rt in rtypes:
        try:
            proc = subprocess.run(
                ["dig", "+short", f"+time={int(max(1, timeout))}", "+tries=1", host, rt],
                capture_output=True, text=True, timeout=timeout + 3,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        values = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        if values:
            out[rt] = values
    return out


def _via_stdlib(host, timeout):
    out = {}
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return out
    v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    if v4:
        out["A"] = v4
    if v6:
        out["AAAA"] = v6
    return out


def _reverse(addresses):
    out = {}
    for a in addresses:
        try:
            out[a] = socket.gethostbyaddr(a)[0]
        except (socket.herror, socket.gaierror, OSError):
            continue
    return out


def run(target, scope, opts):
    addresses = scope.check(target)
    timeout = float(opts.get("timeout", 5))
    rtypes = opts.get("record_types") or RECORD_TYPES

    backend = "stdlib"
    records = {}
    try:
        records = _via_dnspython(target, rtypes, timeout)
        backend = "dnspython"
    except ImportError:
        if shutil.which("dig"):
            records = _via_dig(target, rtypes, timeout)
            backend = "dig"
        else:
            records = _via_stdlib(target, timeout)

    if not records:
        records = _via_stdlib(target, timeout)

    return {
        "target": target,
        "backend": backend,
        "records": records,
        "resolved": addresses,
        "reverse": _reverse(addresses) if opts.get("reverse", True) else {},
    }
