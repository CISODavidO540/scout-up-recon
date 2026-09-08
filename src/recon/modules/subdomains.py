"""Subdomain discovery by DNS resolution of a wordlist.

This resolves names; it never sends traffic to the discovered hosts. Every hit
is still re-checked against scope before it is reported, so a wildcard record
pointing off-scope cannot smuggle a target into the results.
"""

from __future__ import annotations

import concurrent.futures
import pathlib
import random
import socket
import string

NAME = "subdomains"
DESCRIPTION = "Discover subdomains by resolving a wordlist against the domain"

DEFAULT_WORDLIST = pathlib.Path(__file__).parent.parent / "data" / "subdomains-top200.txt"


def _resolve(name):
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, UnicodeError):
        return None
    return sorted({i[4][0] for i in infos})


def _wildcard_addresses(domain, samples=3):
    """Detect a wildcard record so it does not turn every word into a hit."""
    seen = set()
    for _ in range(samples):
        junk = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        addrs = _resolve(f"{junk}.{domain}")
        if addrs:
            seen.update(addrs)
        else:
            return set()
    return seen


def load_words(path=None):
    p = pathlib.Path(path) if path else DEFAULT_WORDLIST
    if not p.exists():
        return []
    words = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            words.append(line)
    return words


def run(target, scope, opts):
    scope.check(target)

    words = load_words(opts.get("wordlist"))
    if not words:
        return {"target": target, "error": "wordlist empty or not found", "found": []}

    wildcard = _wildcard_addresses(target)
    workers = min(int(opts.get("concurrency", scope.max_concurrency)) * 2, 60)

    found, skipped_out_of_scope = [], []

    def check(word):
        name = f"{word}.{target}"
        addrs = _resolve(name)
        if not addrs:
            return None
        if wildcard and set(addrs) <= wildcard:
            return None
        return {"name": name, "addresses": addrs}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(check, words):
            if not res:
                continue
            try:
                scope.check(res["name"])
            except Exception as exc:
                skipped_out_of_scope.append({"name": res["name"], "reason": str(exc)})
                continue
            found.append(res)

    found.sort(key=lambda r: r["name"])
    return {
        "target": target,
        "words_tried": len(words),
        "wildcard_detected": sorted(wildcard) if wildcard else None,
        "found": found,
        "skipped_out_of_scope": skipped_out_of_scope,
    }
