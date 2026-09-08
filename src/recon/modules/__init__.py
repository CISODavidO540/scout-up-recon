"""Reconnaissance modules. Each exposes run(target, scope, opts) -> dict."""

from . import (  # noqa: F401
    dns_enum, http_probe, ports, robots, subdomains, tech, traceroute, whois_lookup,
)

REGISTRY = {
    "dns": dns_enum,
    "whois": whois_lookup,
    "traceroute": traceroute,
    "subdomains": subdomains,
    "ports": ports,
    "http": http_probe,
    "tech": tech,
    "robots": robots,
}

# Passive and cheap first, loud and slow last.
DEFAULT_ORDER = ["dns", "whois", "traceroute", "subdomains", "ports", "http", "tech", "robots"]
