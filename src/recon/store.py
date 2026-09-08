"""Shared store for finished scans.

Both entry points write here, so a scan run from the terminal shows up in the
dashboard's history and either side can write a report from it afterwards.
Records are plain JSON on disk; there is no database and nothing to start.

The store is capped. Recon output names hosts and open services, so keeping
every scan forever on a shared lab machine is a liability, not a feature.
"""

from __future__ import annotations

import json
import pathlib
import re
import uuid

HISTORY_DIR = pathlib.Path("out/scans")
MAX_HISTORY = 50

_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def save(record, directory=HISTORY_DIR) -> pathlib.Path:
    """Write one finished scan and prune anything past MAX_HISTORY."""
    d = pathlib.Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{record['id']}.json"
    path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    files = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime)
    for stale in files[:-MAX_HISTORY]:
        stale.unlink(missing_ok=True)
    return path


def load(scan_id, directory=HISTORY_DIR):
    """Return one saved record, or None.

    A unique id prefix is enough, so you can type the first few characters the
    listing showed instead of the whole thing.
    """
    if not scan_id or not _ID.match(str(scan_id)):
        return None
    d = pathlib.Path(directory)
    p = d / f"{scan_id}.json"
    if not p.exists():
        matches = sorted(d.glob(f"{scan_id}*.json")) if d.exists() else []
        if len(matches) != 1:
            return None
        p = matches[0]
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def recent(limit=25, directory=HISTORY_DIR):
    """Summaries of saved scans, newest first."""
    d = pathlib.Path(directory)
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue  # a truncated record must not hide the rest of the history
        results = rec.get("results") or {}
        out.append({
            "id": rec.get("id"),
            "target": rec.get("target"),
            "finished": rec.get("finished"),
            "modules": rec.get("modules", []),
            "source": rec.get("source", "?"),
            "open_ports": len((results.get("ports") or {}).get("open", [])),
            "subdomains": len((results.get("subdomains") or {}).get("found", [])),
        })
        if len(out) >= limit:
            break
    return out
