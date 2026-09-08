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

# GNU traceroute writes "1  10.0.0.1", tracepath writes "1:  10.0.0.1", and
# tracepath also emits a "1?:" probe line for the local MTU discovery step.
# Matching only the first form silently dropped every hop on tracepath while
# still reporting success, so the colon and the "?" are both optional here.
HOP_RE = re.compile(r"^\s*(\d+)\??:?\s+(.*)$")

#: How each tool says a hop did not answer.
_NO_REPLY = ("no reply", "*")


def _pick_binary():
    for name, args in (
        ("traceroute", ["-n", "-q", "1", "-w", "2", "-m"]),
        ("tracepath", ["-n", "-m"]),
        # Windows ships its own, with the hop limit spelled differently.
        ("tracert", ["-d", "-w", "2000", "-h"]),
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
            # Deliberately not "timeout": that one is the per-connection
            # budget the ports module uses, and at its 3s default a
            # multi-hop trace was killed before it could finish.
            timeout=float(opts.get("traceroute_timeout", 60)),
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
        if not rest or rest.startswith("[LOCALHOST]"):
            continue  # tracepath's MTU probe line, not a hop
        lowered = rest.lower()
        responded = not any(lowered.startswith(marker) for marker in _NO_REPLY)
        hops.append({
            "hop": int(m.group(1)),
            "detail": rest,
            "address": rest.split()[0] if responded else None,
            "responded": responded,
        })

    # tracepath probes a hop more than once; one line per hop reads better and
    # matches what traceroute -q 1 already produces.
    deduped = {}
    for hop in hops:
        if hop["hop"] not in deduped or hop["responded"]:
            deduped.setdefault(hop["hop"], hop)
    hops = [deduped[k] for k in sorted(deduped)]

    return {
        "target": target, "available": True, "binary": binary,
        "scanned_host": host, "hops": hops,
        "hop_count": len(hops),
        "silent_hops": sum(1 for h in hops if not h["responded"]),
    }
