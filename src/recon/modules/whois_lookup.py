"""WHOIS lookup via the system `whois` binary.

Registration data is public and this touches the registry, not the target, but
it still runs behind the scope check so every recorded action ties to one
authorized target.
"""

from __future__ import annotations

import re
import shutil
import subprocess

NAME = "whois"
DESCRIPTION = "Registration and ownership data from the system whois client"

FIELDS = [
    ("registrar", r"^\s*Registrar:\s*(.+)$"),
    ("created", r"^\s*Creation Date:\s*(.+)$"),
    ("updated", r"^\s*Updated Date:\s*(.+)$"),
    ("expires", r"^\s*Registry Expiry Date:\s*(.+)$"),
    ("org", r"^\s*(?:Registrant Organization|OrgName):\s*(.+)$"),
    ("country", r"^\s*(?:Registrant Country|Country):\s*(.+)$"),
    ("netrange", r"^\s*(?:NetRange|inetnum):\s*(.+)$"),
    ("cidr", r"^\s*CIDR:\s*(.+)$"),
]


def run(target, scope, opts):
    scope.check(target)
    if not shutil.which("whois"):
        return {"target": target, "available": False,
                "note": "whois binary not installed (apt install whois)"}

    try:
        proc = subprocess.run(
            ["whois", target], capture_output=True, text=True,
            timeout=float(opts.get("whois_timeout", 15)),
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"target": target, "available": True, "error": str(exc)}

    text = proc.stdout
    summary = {}
    for key, pattern in FIELDS:
        m = re.search(pattern, text, re.M | re.I)
        if m:
            summary[key] = m.group(1).strip()

    nameservers = sorted({
        m.group(1).strip().lower()
        for m in re.finditer(r"^\s*Name Server:\s*(.+)$", text, re.M | re.I)
    })
    if nameservers:
        summary["nameservers"] = nameservers

    return {
        "target": target,
        "available": True,
        "summary": summary,
        "raw_lines": len(text.splitlines()),
        "raw": text if opts.get("keep_raw") else None,
    }
