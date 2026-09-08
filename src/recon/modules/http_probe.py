"""HTTP/HTTPS fingerprinting and security-header audit.

Sends one GET per scheme with redirects followed manually so the redirect chain
itself is evidence. Uses requests when available, urllib otherwise.
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

NAME = "http"
DESCRIPTION = "Fetch HTTP(S) headers, page title, and audit security headers"

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS — forces HTTPS on later visits",
    "content-security-policy": "CSP — limits where scripts may load from",
    "x-frame-options": "Clickjacking protection (superseded by CSP frame-ancestors)",
    "x-content-type-options": "Stops MIME sniffing",
    "referrer-policy": "Controls how much URL leaks to third parties",
    "permissions-policy": "Restricts browser feature access",
}

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                 "x-generator", "x-drupal-cache", "x-runtime"]

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

_ORIG_GETADDRINFO = socket.getaddrinfo
_forced = False


def _force_ipv4():
    """Restrict urllib's resolution to IPv4 for the rest of the process."""
    global _forced
    if _forced:
        return
    def _v4_only(host, port, family=0, *args, **kwargs):
        return _ORIG_GETADDRINFO(host, port, socket.AF_INET, *args, **kwargs)
    socket.getaddrinfo = _v4_only
    _forced = True


def _fetch(url, timeout, user_agent, max_redirects=5):
    chain = []
    current = url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for _ in range(max_redirects + 1):
        req = urllib.request.Request(current, headers={"User-Agent": user_agent})

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
        )
        try:
            resp = opener.open(req, timeout=timeout)
            status, headers, body = resp.status, dict(resp.headers), resp.read(65536)
        except urllib.error.HTTPError as exc:
            status, headers, body = exc.code, dict(exc.headers), exc.read(65536)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return None, chain, str(exc)

        chain.append({"url": current, "status": status})
        location = headers.get("Location") or headers.get("location")
        if status in (301, 302, 303, 307, 308) and location:
            current = urllib.parse.urljoin(current, location)
            continue
        return {"status": status, "headers": headers, "body": body}, chain, None

    return None, chain, "too many redirects"


def _audit(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    missing = [name for name in SECURITY_HEADERS if name not in lower]
    present = {name: lower[name] for name in SECURITY_HEADERS if name in lower}
    leaks = {h: lower[h] for h in LEAKY_HEADERS if h in lower}
    return {
        "present": present,
        "missing": missing,
        "version_disclosure": leaks,
        "cookies_without_flags": [
            c for c in headers.get("Set-Cookie", "").split("\n")
            if c and ("httponly" not in c.lower() or "secure" not in c.lower())
        ],
    }


def run(target, scope, opts):
    addresses = scope.check(target)
    timeout = float(opts.get("timeout", 8))

    # Same trap as the port scanner: a host with an AAAA record on an IPv4-only
    # network fails with ENETUNREACH rather than anything meaningful. If the
    # name has a v4 address, pin the socket to AF_INET so the Host header and
    # TLS SNI still carry the real name.
    if any(":" not in a for a in addresses):
        _force_ipv4()
    ua = opts.get("user_agent", "recon/0.1 (authorized security assessment)")
    schemes = opts.get("schemes") or ["https", "http"]

    results = {}
    for scheme in schemes:
        url = f"{scheme}://{target}"
        resp, chain, err = _fetch(url, timeout, ua)
        if err and not resp:
            results[scheme] = {"reachable": False, "error": err, "chain": chain}
            continue
        title_match = TITLE_RE.search(resp["body"])
        title = None
        if title_match:
            title = " ".join(
                title_match.group(1).decode("utf-8", "replace").split()
            )[:150]
        results[scheme] = {
            "reachable": True,
            "final_status": resp["status"],
            "redirect_chain": chain,
            "title": title,
            "server": resp["headers"].get("Server"),
            "headers": dict(resp["headers"]),
            "security": _audit(resp["headers"]),
        }
    return {"target": target, "results": results}
