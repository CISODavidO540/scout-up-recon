"""Technology fingerprinting from response headers and page markup.

Signature matching only. It never probes for a version by trying an exploit, so
a hit here is a lead to verify, not a finding.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from .http_probe import _force_ipv4

NAME = "tech"
DESCRIPTION = "Fingerprint server software, frameworks and CMS from responses"

HEADER_SIGNATURES = {
    "server": "Web server",
    "x-powered-by": "Application platform",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Site generator",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
    "x-varnish": "Varnish cache",
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-vercel-id": "Vercel",
    "x-nf-request-id": "Netlify",
    "x-github-request-id": "GitHub Pages",
    "fastly-debug-digest": "Fastly",
}

BODY_SIGNATURES = [
    ("WordPress", r"/wp-content/|/wp-includes/|<meta name=[\"']generator[\"'] content=[\"']WordPress"),
    ("Drupal", r"/sites/(all|default)/|Drupal\.settings"),
    ("Joomla", r"/media/jui/|com_content"),
    ("React", r"__REACT_DEVTOOLS|data-reactroot|_next/static"),
    ("Next.js", r"/_next/static|__NEXT_DATA__"),
    ("Vue", r"data-v-[0-9a-f]{8}|__VUE_"),
    ("Angular", r"ng-version=|angular\.min\.js"),
    ("jQuery", r"jquery[.-][\d.]+(\.min)?\.js"),
    ("Bootstrap", r"bootstrap[.-][\d.]+(\.min)?\.(js|css)"),
    ("Laravel", r"XSRF-TOKEN|laravel_session"),
    ("Django", r"csrfmiddlewaretoken|__admin_media_prefix__"),
    ("Cloudflare challenge", r"cdn-cgi/challenge-platform"),
]

GENERATOR_RE = re.compile(
    rb"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I)


def run(target, scope, opts):
    addresses = scope.check(target)
    if any(":" not in a for a in addresses):
        _force_ipv4()
    timeout = float(opts.get("timeout", 8))
    ua = opts.get("user_agent", "recon/0.1 (authorized security assessment)")
    scheme = opts.get("scheme") or "http"

    url = f"{scheme}://{target}/"
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            body = resp.read(300_000)
            status = resp.status
    except urllib.error.HTTPError as exc:
        headers, body, status = dict(exc.headers), exc.read(300_000), exc.code
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"target": target, "reachable": False, "error": str(exc)}

    lower = {k.lower(): v for k, v in headers.items()}
    from_headers = {
        HEADER_SIGNATURES[k]: lower[k] for k in HEADER_SIGNATURES if k in lower
    }

    text = body.decode("utf-8", "replace")
    from_body = [name for name, pattern in BODY_SIGNATURES
                 if re.search(pattern, text, re.I)]

    generator = None
    m = GENERATOR_RE.search(body)
    if m:
        generator = m.group(1).decode("utf-8", "replace")

    cookies = sorted({
        c.split("=", 1)[0].strip()
        for c in headers.get("Set-Cookie", "").replace("\n", ";").split(";")
        if "=" in c
    })

    return {
        "target": target, "reachable": True, "status": status, "url": url,
        "from_headers": from_headers, "from_body": from_body,
        "generator": generator, "cookie_names": cookies[:15],
    }
