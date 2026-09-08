"""TCP connect scan with optional banner grabbing.

A connect scan completes the handshake, so it is loud and it lands in the
target's logs. That is the correct trade for coursework and authorized testing:
no raw sockets, no root, and nothing that looks like evasion.
"""

from __future__ import annotations

import concurrent.futures
import socket
import ssl
import time

NAME = "ports"
DESCRIPTION = "TCP connect scan of common or specified ports, with banners"

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432,
    5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017,
]

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http-alt",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

TLS_PORTS = {443, 465, 993, 995, 8443}


def parse_ports(spec):
    """Accept '80', '1-1024', '22,80,443', or 'top'."""
    if not spec or spec == "top":
        return list(TOP_PORTS)
    out = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            out.update(range(max(1, lo), min(65535, hi) + 1))
        else:
            out.add(int(part))
    return sorted(p for p in out if 1 <= p <= 65535)


def _grab_banner(sock, port, timeout):
    """Read whatever the service volunteers. Nudge HTTP, since it waits."""
    try:
        sock.settimeout(timeout)
        if port in (80, 8080, 8000, 3000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
        return data.decode("utf-8", "replace").strip() or None
    except (socket.timeout, OSError):
        return None


def _tls_info(host, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "subject": dict(x[0] for x in cert.get("subject", ())) if cert else None,
                    "not_after": cert.get("notAfter") if cert else None,
                }
    except (OSError, ssl.SSLError, socket.timeout):
        return None


def _probe(host, port, timeout, banners):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            result = {
                "port": port,
                "state": "open",
                "service": SERVICE_HINTS.get(port, "unknown"),
                "rtt_ms": elapsed,
            }
            if banners:
                b = _grab_banner(sock, port, timeout)
                if b:
                    result["banner"] = b[:200]
            return result
    except socket.timeout:
        return {"port": port, "state": "filtered"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed"}
    except OSError as exc:
        # ENETUNREACH/EHOSTUNREACH means we cannot reach this address family at
        # all, not that the port is interesting. Surface it as unreachable so it
        # does not read as 50 mysterious errors.
        return {"port": port, "state": "unreachable", "error": str(exc)}


def run(target, scope, opts):
    addresses = scope.check(target)
    host = addresses[0] if addresses else target

    ports_list = parse_ports(opts.get("ports", "top"))
    timeout = float(opts.get("timeout", 2))
    banners = bool(opts.get("banners", True))
    workers = min(int(opts.get("concurrency", scope.max_concurrency)), 100)

    open_ports, other = [], {"closed": 0, "filtered": 0, "unreachable": 0, "error": 0}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe, host, p, timeout, banners): p for p in ports_list}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res["state"] == "open":
                open_ports.append(res)
            else:
                other[res["state"]] = other.get(res["state"], 0) + 1

    open_ports.sort(key=lambda r: r["port"])

    if not open_ports and other.get("unreachable") == len(ports_list):
        return {
            "target": target, "scanned_host": host,
            "ports_scanned": len(ports_list), "open": [], "summary": other,
            "error": (f"no route to {host} — every connection failed as unreachable. "
                      "If this is an IPv6 address on an IPv4-only network, that is why."),
        }

    if opts.get("tls", True):
        for entry in open_ports:
            if entry["port"] in TLS_PORTS:
                info = _tls_info(host, entry["port"], timeout)
                if info:
                    entry["tls"] = info

    return {
        "target": target,
        "scanned_host": host,
        "ports_scanned": len(ports_list),
        "open": open_ports,
        "summary": other,
    }
