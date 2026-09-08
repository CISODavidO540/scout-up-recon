"""Command-line entry point.

Refuses to do anything without a scope file. That is the whole design: the
authorization boundary is not a flag you remember to set, it is the only way
the program starts.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import sys

from . import __version__, output, paths, report, store
from .modules import DEFAULT_ORDER, REGISTRY
from .scope import OutOfScope, Scope, ScopeError

#: Resolved per run, not at import: where the scope file lives depends on
#: whether you are standing in a checkout or running an installed copy.


def build_parser():
    p = argparse.ArgumentParser(
        prog="recon",
        description="Scope-enforced reconnaissance for authorized engagements.",
        epilog=(
            "Every target is checked against the scope file before any packet is sent. "
            "There is no flag to disable that check."
        ),
    )
    p.add_argument("target", nargs="?", help="domain or IP to enumerate")
    p.add_argument("--init", action="store_true",
                   help="write a starter scope file to the default location and exit")
    p.add_argument("-s", "--scope", default=None,
                   help="scope file (default: the first of $RECON_SCOPE, "
                        "<checkout>/config/scope.json, or the per-user config dir)")
    p.add_argument("-m", "--modules", default="dns,whois,http",
                   help="comma-separated modules, or 'all' (default: dns,whois,http)")
    p.add_argument("-p", "--ports", default="top",
                   help="ports for the ports module: 'top', '1-1024', '22,80,443'")
    p.add_argument("-w", "--wordlist", help="wordlist for the subdomains module")
    p.add_argument("-c", "--concurrency", type=int,
                   help="override the scope file's max_concurrency")
    p.add_argument("-t", "--timeout", type=float, default=None,
                   help="per-connection timeout in seconds")
    p.add_argument("-o", "--out", help="write raw JSON results to this path")
    p.add_argument("-r", "--report", nargs="?", const="", metavar="PATH",
                   help="write a Markdown findings report; bare flag writes into reports/")
    p.add_argument("--markdown", metavar="PATH",
                   help="alias for --report PATH")
    p.add_argument("--results", action="store_true",
                   help="list saved scans and exit")
    p.add_argument("--show", metavar="ID",
                   help="reprint a saved scan; combine with --report to write it up")
    p.add_argument("--no-banners", action="store_true", help="skip banner grabbing")
    p.add_argument("--list-modules", action="store_true", help="show modules and exit")
    p.add_argument("--check", action="store_true",
                   help="run the scope check on the target and exit without scanning")
    p.add_argument("--serve", action="store_true",
                   help="start the local dashboard instead of scanning")
    p.add_argument("--port", type=int, default=8787, help="dashboard port (default 8787)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress the banner")
    p.add_argument("-V", "--version", action="version", version=f"recon {__version__}")
    return p


def resolve_modules(spec):
    if spec == "all":
        return list(DEFAULT_ORDER)
    wanted = [m.strip() for m in spec.split(",") if m.strip()]
    unknown = [m for m in wanted if m not in REGISTRY]
    if unknown:
        raise SystemExit(
            f"unknown module(s): {', '.join(unknown)}\n"
            f"available: {', '.join(DEFAULT_ORDER)}"
        )
    return sorted(wanted, key=lambda m: DEFAULT_ORDER.index(m))


def _write_report(args, record):
    """Write the Markdown findings report, if either flag asked for one."""
    path = args.markdown if args.markdown else args.report
    if path is None:
        return
    if not (record.get("results") or {}):
        print(output.yellow("nothing to report: that scan produced no results"),
              file=sys.stderr)
        return
    if path:
        p = pathlib.Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.build(record), encoding="utf-8")
    else:
        p = report.write(record)
    findings = report.derive_findings(record["results"])
    print(output.dim(f"report: {p}  ({len(findings)} finding(s))"))


def _init_scope(dest=None):
    """Put a starter scope file where this machine expects to find it.

    Telling someone to `cp` a file out of a site-packages directory they have
    to locate first is a bad first five minutes. This does it for them, and
    refuses to overwrite an existing engagement.
    """
    target = pathlib.Path(dest) if dest else paths.scope_path()
    if target.exists():
        print(output.yellow(f"scope file already exists: {target}"), file=sys.stderr)
        print("Edit it, or pass --scope to use a different one.", file=sys.stderr)
        return 2
    example = paths.example_scope()
    if example is None:
        print("cannot find the packaged scope.example.json", file=sys.stderr)
        return 2
    data = json.loads(example.read_text(encoding="utf-8"))
    # The example ships fixed dates so it reads clearly, but a file generated
    # today should open today — otherwise a new user's first run is refused by
    # an engagement window that expired before they installed anything.
    today = _dt.date.today()
    data["valid_from"] = today.isoformat()
    data["valid_until"] = (today + _dt.timedelta(days=90)).isoformat()
    data["notes"] = ("Edit in_scope before scanning. Never commit this file: it names "
                     "real targets and who authorized them.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {target}")
    print("Edit it before scanning: it decides what you are allowed to touch.")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.init:
        return _init_scope(args.scope)

    if args.serve:
        from .webapp import serve
        return serve(args.scope, args.port)

    if args.results:
        rows = store.recent()
        if not rows:
            print("no saved scans yet")
            return 0
        print(f"{'ID':<14}{'TARGET':<28}{'WHEN':<21}{'FROM':<11}MODULES")
        for r in rows:
            mods = ", ".join(r["modules"])
            extra = []
            if r["open_ports"]:
                extra.append(f"{r['open_ports']} open")
            if r["subdomains"]:
                extra.append(f"{r['subdomains']} subs")
            if extra:
                mods += f"  ({', '.join(extra)})"
            print(f"{r['id']:<14}{str(r['target'])[:26]:<28}"
                  f"{str(r['finished'])[:19]:<21}{r['source'][:9]:<11}{mods}")
        return 0

    if args.show:
        record = store.load(args.show)
        if record is None:
            print(f"no saved scan matching '{args.show}'", file=sys.stderr)
            return 2
        print(output.bold(f"{record.get('target')}  —  {record.get('finished')}"))
        print(output.dim(f"engagement: {record.get('engagement') or '—'}  "
                         f"authorized by: {record.get('authorized_by') or '—'}"))
        print()
        for name, data in (record.get("results") or {}).items():
            for line in output.render(name, data):
                print(line)
            print()
        _write_report(args, record)
        return 0

    if args.list_modules:
        print("Available modules:\n")
        for name in DEFAULT_ORDER:
            print(f"  {name:<12} {REGISTRY[name].DESCRIPTION}")
        return 0

    if not args.target:
        build_parser().print_usage(sys.stderr)
        print("\nerror: a target is required", file=sys.stderr)
        return 2

    try:
        scope = Scope.load(args.scope or paths.scope_path())
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(scope.banner())
        print()

    try:
        addresses = scope.check(args.target)
    except OutOfScope as exc:
        print(output.red(f"REFUSED: {exc}"), file=sys.stderr)
        return 3

    if args.check:
        print(output.green(f"IN SCOPE: {args.target}"))
        if addresses:
            print(f"  resolves to: {', '.join(addresses)}")
        return 0

    modules = resolve_modules(args.modules)
    opts = {
        "ports": args.ports,
        "wordlist": args.wordlist,
        "banners": not args.no_banners,
    }
    if args.concurrency:
        opts["concurrency"] = args.concurrency
    if args.timeout is not None:
        opts["timeout"] = args.timeout

    meta = {
        "id": store.new_id(),
        "source": "cli",
        "target": args.target,
        "engagement": scope.engagement,
        "authorized_by": scope.authorized_by,
        "authorization_ref": scope.authorization_ref,
        "scope_file": scope.source_path,
        "started": output.timestamp(),
        "modules": modules,
        "tool_version": __version__,
    }

    results, failed = {}, []
    for name in modules:
        module = REGISTRY[name]
        try:
            data = module.run(args.target, scope, opts)
        except OutOfScope as exc:
            print(output.red(f"REFUSED during {name}: {exc}"), file=sys.stderr)
            return 3
        except KeyboardInterrupt:
            print(output.yellow("\ninterrupted"), file=sys.stderr)
            break
        except Exception as exc:  # a module failing must not lose the rest
            failed.append((name, str(exc)))
            print(output.red(f"   {name} failed: {exc}"), file=sys.stderr)
            continue
        results[name] = data
        for line in output.render(name, data):
            print(line)
        print()

    record = dict(meta)
    record["finished"] = output.timestamp()
    record["results"] = results
    record["failed"] = dict(failed)

    saved = store.save(record)
    print(output.dim(f"saved scan {record['id']}  ({saved})"))

    if args.out:
        p = output.write_json(results, record, args.out)
        print(output.dim(f"JSON results: {p}"))
    _write_report(args, record)

    return 0


if __name__ == "__main__":
    sys.exit(main())
