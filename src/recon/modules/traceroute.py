"""Network path via the system traceroute/tracepath binary.

Useful for showing where a target sits relative to you: how many hops, whether
a CDN or load balancer terminates the path early, which upstream carries it.
Shells out because raw-socket traceroute needs privileges this tool does not want.
"""

from __future__ import annotations

import re
import shutil
import subprocess

NAME = "traceroute"
DESCRIPTION = "Trace the network path to the target (system traceroute)"

HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def _pick_binary():
    for name, args in (
        ("traceroute", ["-n", "-q", "1", "-w", "2", "-m"]),
        ("tracepath", ["-n", "-m"]),
    ):
        path = shutil.which(name)
        if path:
            return name, args
    return None, None


def run(target, scope, opts):
    addresses = scope.check(target)
    host = addresses[0] if addresses else target

    binary, base_args = _pick_binary()
    if not binary:
        return {"target": target, "available": False,
                "note": "no traceroute or tracepath binary (apt install traceroute)"}

    max_hops = str(int(opts.get("max_hops", 20)))
    try:
        proc = subprocess.run(
            [binary, *base_args, max_hops, host],
            capture_output=True, text=True,
            timeout=float(opts.get("timeout", 60)),
        )
    except subprocess.TimeoutExpired:
        return {"target": target, "available": True, "error": "traceroute timed out"}
    except OSError as exc:
        return {"target": target, "available": True, "error": str(exc)}

    hops = []
    for line in proc.stdout.splitlines():
        m = HOP_RE.match(line)
        if not m:
            continue
        rest = m.group(2).strip()
        hops.append({
            "hop": int(m.group(1)),
            "detail": rest,
            "responded": "*" not in rest.split()[0] if rest else False,
        })

    return {
        "target": target, "available": True, "binary": binary,
        "scanned_host": host, "hops": hops,
        "hop_count": len(hops),
        "silent_hops": sum(1 for h in hops if not h["responded"]),
    }
