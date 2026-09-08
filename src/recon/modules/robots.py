"""Well-known files: robots.txt, sitemap.xml, security.txt.

The first stop on any web recon. robots.txt routinely names admin paths and
staging hosts the operator would rather you did not find; security.txt tells you
who to report to, which matters for the disclosure half of an engagement.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from .http_probe import _force_ipv4

NAME = "robots"
DESCRIPTION = "Fetch robots.txt, sitemap.xml and security.txt"

PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
]

INTERESTING = re.compile(
    r"(admin|login|backup|config|private|internal|staging|dev|test|api|"
    r"wp-admin|phpmyadmin|\.git|\.env|db|sql|dump)", re.I
)


def _get(url, timeout, ua):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, str(exc)


def run(target, scope, opts):
    addresses = scope.check(target)
    if any(":" not in a for a in addresses):
        _force_ipv4()
    timeout = float(opts.get("timeout", 8))
    ua = opts.get("user_agent", "recon/0.1 (authorized security assessment)")
    scheme = opts.get("scheme") or "http"

    found, missing = {}, []
    for path in PATHS:
        status, body = _get(f"{scheme}://{target}{path}", timeout, ua)
        if status == 200 and body:
            entry = {"status": status, "bytes": len(body),
                     "preview": body[:1500]}
            if path.endswith("robots.txt"):
                disallowed = [
                    m.group(1).strip()
                    for m in re.finditer(r"^\s*Disallow:\s*(\S+)", body, re.M | re.I)
                ]
                entry["disallowed"] = disallowed
                entry["notable"] = sorted({d for d in disallowed if INTERESTING.search(d)})
                sitemaps = [m.group(1).strip() for m in
                            re.finditer(r"^\s*Sitemap:\s*(\S+)", body, re.M | re.I)]
                if sitemaps:
                    entry["sitemaps"] = sitemaps
            if path.endswith("sitemap.xml"):
                urls = re.findall(r"<loc>\s*([^<]+?)\s*</loc>", body)
                entry["url_count"] = len(urls)
                entry["sample_urls"] = urls[:25]
                entry.pop("preview", None)
            found[path] = entry
        else:
            missing.append(path)

    return {"target": target, "scheme": scheme, "found": found, "missing": missing}
