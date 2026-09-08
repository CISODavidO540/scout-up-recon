"""Local dashboard for the recon toolkit.

Binds to 127.0.0.1 only. A scanner that answers on a campus or client network is
itself an exposure, so the listen address is not configurable from the CLI: run
it over an SSH tunnel if you need it from another machine.

Stdlib only, same as the rest of the package. No build step, no framework.
"""

from __future__ import annotations

import datetime as _dt
import json
import pathlib
import threading
import traceback
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, output, report, store
from .modules import DEFAULT_ORDER, REGISTRY
from .scope import OutOfScope, Scope, ScopeError

STATIC = pathlib.Path(__file__).parent / "data"
REPORT_DIR = pathlib.Path("reports")

_lock = threading.Lock()
_jobs: dict = {}


def _load_scope(path):
    return Scope.load(path)


def _scope_payload(scope):
    return {
        "engagement": scope.engagement,
        "authorized_by": scope.authorized_by,
        "authorization_ref": scope.authorization_ref,
        "valid_from": scope.valid_from.isoformat(),
        "valid_until": scope.valid_until.isoformat(),
        "window_open": scope.window_open(),
        "in_scope": [str(v) for _, v in scope.in_scope],
        "out_of_scope": [str(v) for _, v in scope.out_of_scope],
        "strict_resolution": scope.strict_resolution,
        "max_concurrency": scope.max_concurrency,
        "source_path": scope.source_path,
    }


def _run_job(job_id, scope_path, target, modules, opts):
    try:
        scope = _load_scope(scope_path)
    except ScopeError as exc:
        with _lock:
            _jobs[job_id].update(state="error", error=f"scope error: {exc}")
        return

    try:
        scope.check(target)
    except OutOfScope as exc:
        with _lock:
            _jobs[job_id].update(state="refused", error=str(exc))
        return

    results, failed = {}, {}
    for name in modules:
        with _lock:
            _jobs[job_id]["running"] = name
        try:
            results[name] = REGISTRY[name].run(target, scope, opts)
        except OutOfScope as exc:
            with _lock:
                _jobs[job_id].update(state="refused", error=str(exc), results=results)
            return
        except Exception as exc:
            failed[name] = str(exc)
            traceback.print_exc()
        with _lock:
            _jobs[job_id]["results"] = results
            _jobs[job_id]["failed"] = failed

    record = {
        "id": job_id,
        "target": target,
        "modules": modules,
        "engagement": scope.engagement,
        "authorized_by": scope.authorized_by,
        "authorization_ref": scope.authorization_ref,
        "source": "dashboard",
        "finished": output.timestamp(),
        "results": results,
        "failed": failed,
    }
    store.save(record)
    with _lock:
        # Carry the authorization fields onto the live job too: a report written
        # straight after a scan reads this dict, not the file on disk.
        _jobs[job_id].update(state="done", running=None, results=results,
                             failed=failed, finished=record["finished"],
                             engagement=record["engagement"],
                             authorized_by=record["authorized_by"],
                             authorization_ref=record["authorization_ref"])


def _reports():
    if not REPORT_DIR.exists():
        return []
    out = []
    for p in sorted(REPORT_DIR.glob("*.md"),
                    key=lambda p: p.stat().st_mtime, reverse=True)[:25]:
        out.append({"file": p.name, "bytes": p.stat().st_size,
                    "modified": _dt.datetime.fromtimestamp(
                        p.stat().st_mtime).strftime("%Y-%m-%dT%H:%M:%S")})
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = f"recon/{__version__}"
    scope_path = "config/scope.json"

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")

    # ---------- helpers ----------

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return {}

    # ---------- routes ----------

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path in ("/", "/index.html"):
            html = (STATIC / "dashboard.html").read_text(encoding="utf-8")
            return self._send(200, html, "text/html; charset=utf-8")

        if path == "/api/scope":
            try:
                return self._send(200, _scope_payload(_load_scope(self.scope_path)))
            except ScopeError as exc:
                return self._send(200, {"error": str(exc)})

        if path == "/api/modules":
            return self._send(200, [
                {"name": n, "description": REGISTRY[n].DESCRIPTION} for n in DEFAULT_ORDER
            ])

        if path == "/api/history":
            return self._send(200, store.recent())

        if path == "/api/reports":
            return self._send(200, _reports())

        if path.startswith("/api/report/"):
            # Serve a previously written report back for preview.
            name = pathlib.Path(urllib.parse.unquote(path.rsplit("/", 1)[-1])).name
            f = REPORT_DIR / name
            if not f.exists() or f.suffix != ".md":
                return self._send(404, {"error": "no such report"})
            return self._send(200, f.read_text(encoding="utf-8"),
                              "text/plain; charset=utf-8")

        if path.startswith("/api/job/"):
            job_id = path.rsplit("/", 1)[-1]
            with _lock:
                job = _jobs.get(job_id)
            if not job:
                rec = store.load(job_id)
                if rec:
                    return self._send(200, {"state": "done", **rec})
                return self._send(404, {"error": "no such job"})
            return self._send(200, job)

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path.startswith("/api/report/"):
            job_id = pathlib.Path(path.rsplit("/", 1)[-1]).name
            with _lock:
                job = _jobs.get(job_id)
            record = dict(job) if job else None
            if record is None:
                record = store.load(job_id)
                if record is None:
                    return self._send(404, {"error": "no such scan"})
            if not record.get("results"):
                return self._send(400, {"error": "that scan produced no results to report on"})
            record.setdefault("id", job_id)
            try:
                out = report.write(record, REPORT_DIR)
            except OSError as exc:
                return self._send(500, {"error": f"could not write report: {exc}"})
            return self._send(201, {"file": out.name, "path": str(out),
                                    "findings": len(report.derive_findings(record["results"]))})

        if path != "/api/scan":
            return self._send(404, {"error": "not found"})

        data = self._body()
        target = (data.get("target") or "").strip()
        if not target:
            return self._send(400, {"error": "target is required"})

        modules = [m for m in (data.get("modules") or ["dns"]) if m in REGISTRY]
        if not modules:
            return self._send(400, {"error": "no valid modules selected"})
        modules.sort(key=DEFAULT_ORDER.index)

        opts = {
            "ports": data.get("ports") or "top",
            "banners": bool(data.get("banners", True)),
            "timeout": float(data.get("timeout") or 3),
        }

        job_id = uuid.uuid4().hex[:12]
        with _lock:
            _jobs[job_id] = {"id": job_id, "state": "running", "target": target,
                             "modules": modules, "running": modules[0],
                             "started": output.timestamp(), "results": {}, "failed": {}}
        threading.Thread(target=_run_job, daemon=True,
                         args=(job_id, self.scope_path, target, modules, opts)).start()
        return self._send(202, {"id": job_id})


def serve(scope_path="config/scope.json", port=8787):
    Handler.scope_path = scope_path
    try:
        Scope.load(scope_path)
    except ScopeError as exc:
        print(f"scope error: {exc}")
        return 2

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"recon dashboard  ->  http://127.0.0.1:{port}")
    print(f"scope file       ->  {scope_path}")
    print(f"reports          ->  {REPORT_DIR.resolve()}")
    print("bound to loopback only; Ctrl-C to stop\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
