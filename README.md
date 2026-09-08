# Scout Up — Recon

**Scout Up** is a reconnaissance toolkit for authorized penetration testing
engagements, with the authorization boundary built into the program rather than
written in the manual. The command it installs is `recon`.

Most recon tools treat scope as documentation. This one treats it as code: `recon`
will not start without a scope file naming who authorized the engagement and the
dates it covers, every target is checked against that file before a single packet
is sent, and **there is no flag to turn the check off**. A target that is not
listed is refused, and the refusal is what gets recorded.

---

## What It Does

Eight modules, run quiet-to-loud.

**Passive** — information from registries and resolvers, not from the target:

| Module | What it collects |
|---|---|
| `dns` | A, AAAA, MX, NS, TXT, CNAME, SOA records |
| `whois` | Registration data: owner, registrar, dates, nameservers |
| `traceroute` | Network path and hop count; shows whether a CDN terminates the path early |
| `subdomains` | Resolves a wordlist against the domain. Finds names only, never contacts them |

**Active** — the target logs these:

| Module | What it does |
|---|---|
| `ports` | TCP connect scan with banner grabbing and TLS certificate extraction |
| `http` | One GET per scheme, redirects followed manually so the chain is evidence; security-header audit |
| `tech` | Fingerprints the stack from headers and page markup (signature matching only) |
| `robots` | `robots.txt`, `sitemap.xml`, `security.txt`; flags admin, backup, `.git`, and `.env` paths |

Results become a Markdown report with findings ranked by severity. Severity stops
at medium on purpose: recon observes what a service advertises about itself, which
is a lead to verify, not a confirmed vulnerability. Every finding states what would
be needed to confirm it.

---

## How It Works

Every scan goes through the same four stages, in this order.

**1. Load the engagement.** `scope.py` reads the JSON scope file into a `Scope`
object. If the file is missing, unreadable, or outside its `valid_from`–`valid_until`
window, the program exits before anything else runs. There is no code path that
reaches a module without a valid scope.

**2. Check the target — twice.** `Scope.check()` matches the target against the
in-scope list (exact names, wildcards, IPs, CIDR ranges), then against the
out-of-scope list, which always wins. Then the name is resolved and **every address
it resolves to is checked again**. This second pass is the important one: a hostname
that resolves onto an excluded address is refused, so a wildcard record or a rebinding
trick cannot walk a scan off-scope after the first check passed.

**3. Dispatch the modules, quiet to loud.** Each module in `modules/` is a plain
function taking a target and returning a dict, so the runner does not care what a
module does. Passive modules ask registries and resolvers; active modules touch the
target and the target logs them. Any host a module *discovers* is fed back through
`Scope.check()` before it is touched, which is what keeps subdomain enumeration from
becoming an unauthorized scan.

**4. Derive findings, then report.** `report.py` turns raw module output into
findings with a severity and a "how to confirm this" line. Severity is capped at
medium by design — recon reads what a service advertises about itself, which is a
lead, not a proven vulnerability. `store.py` keeps the raw JSON so the same scan can
be re-read or written up later without re-running it, and `webapp.py` serves the
dashboard over the same store the CLI uses.

The dashboard is the same pipeline with a browser in front of it. It binds to
`127.0.0.1` only, and that address is not configurable.

## How to Install

Python 3.9 or newer. **No dependencies are required.**

```bash
git clone https://github.com/CISODavidO540/scout-up-recon.git
cd scout-up-recon
python3 -m pytest tests/ -q
```

That last command should print `42 passed`. If it does, you are installed.

The tool runs from source with no build step:

```bash
PYTHONPATH=src python3 -m recon --list-modules
```

To install it as a `recon` command available from anywhere:

```bash
pip install .
```

Then set up your engagement file. This works from any directory:

```bash
recon --init
```

It writes a starter scope file to the right place for your platform and tells
you where that is. Edit it before you scan anything — that file decides what
you are allowed to touch.

### Optional extras

Everything degrades gracefully. Each of these makes one module better and none of
them are needed:

| Package or binary | Improves | Fallback when missing |
|---|---|---|
| `dnspython` | `dns` | shells out to `dig`, then stdlib lookups |
| `requests` | `http` | `urllib` from the standard library |
| `whois` (system binary) | `whois` | module reports unavailable, scan continues |
| `traceroute` or `tracepath` | `traceroute` | module reports unavailable, scan continues |

The zero-dependency design is deliberate. Lab and exam machines frequently forbid
installing packages, and a recon tool that cannot run there is not useful.

---

## Step-by-Step Instructions

**1. Write a scope file.** Generate one and edit it:

```bash
recon --init
```

From a checkout you can copy the example directly instead:

```bash
cp config/scope.example.json config/scope.json
```

```json
{
  "engagement": "Example engagement",
  "authorized_by": "Name of the person who authorized it",
  "authorization_ref": "Where that authorization is written down",
  "valid_from": "2026-09-03",
  "valid_until": "2026-12-04",
  "in_scope": ["target.lab.local", "10.0.2.0/24"],
  "out_of_scope": ["10.0.2.1"],
  "max_concurrency": 8,
  "strict_resolution": false
}
```

`in_scope` accepts hostnames, IP addresses, and CIDR ranges. `out_of_scope` always
wins over `in_scope`. Outside the `valid_from`–`valid_until` window the tool refuses
to run at all.

**2. Confirm a target is authorized before scanning it:**

```bash
PYTHONPATH=src python3 -m recon target.lab.local --check
```

**3. Scan:**

```bash
PYTHONPATH=src python3 -m recon target.lab.local -m all --report
```

**4. Or use the dashboard:**

```bash
PYTHONPATH=src python3 -m recon --serve
```

Then open <http://127.0.0.1:8787>.

### Common flags

| Flag | Effect |
|---|---|
| `-m dns,ports,http` | Pick modules; `-m all` runs everything |
| `-p top` / `-p 1-1024` / `-p 22,80,443` | Ports for the `ports` module |
| `--check` | Run the scope check and exit without scanning |
| `-r, --report [PATH]` | Write a Markdown findings report; bare flag writes into the reports directory |
| `-o, --out PATH` | Write raw JSON results |
| `--results` | List saved scans |
| `--show ID` | Reprint a saved scan; add `--report` to write it up later |
| `--init` | Write a starter scope file to the default location and exit |
| `--serve` | Start the local dashboard |
| `--no-banners` | Skip banner grabbing |

Exit codes: `0` success, `2` bad usage or unreadable scope file, `3` **refused by
scope**. A `3` in a script means the tool stopped you, not that it broke.

---

## Security and privacy

This tool produces sensitive output and takes actions that are illegal without
permission. The design assumes both.

### Authorization is enforced, not documented

- The program will not start without a scope file. There is no default scope, no
  `--force`, and no environment variable that bypasses the check.
- Every target passes `Scope.check()` before any module runs. Modules re-check any
  host they discover, so a wildcard DNS record cannot walk a scan onto an
  unauthorized host.
- Hostnames are resolved and **every resulting address is re-checked** against the
  exclusion list. A name that resolves onto an excluded IP is refused. This blocks
  DNS rebinding from moving a scan off-scope mid-run.
- The engagement window is enforced on every run, so authorization expires on its
  own rather than depending on you to remember.

### Where your files are kept

Nothing is written to a shared or system-wide location. Paths resolve in this
order, and the first match wins:

| | Scope file | Scan history and reports |
|---|---|---|
| Explicit | `--scope PATH`, or `RECON_SCOPE` | `RECON_HOME` |
| Inside a checkout | `<checkout>/config/scope.json` | `<checkout>/out/`, `<checkout>/reports/` |
| Installed copy | `~/.config/scout-up/scope.json` | `~/.local/share/scout-up/` |

On Windows both fall under `%LOCALAPPDATA%\scout-up`. A checkout is detected by
walking up from the current directory, so the repository workflow keeps working
from any subdirectory of it, and an installed copy run from your home directory
no longer reports the scope file missing.

### Naming your own deployment

The name in the dashboard header is not hardcoded. Set `app_name` in your scope
file, or `RECON_APP_NAME` in the environment, and that name is what the page and
the browser tab show:

```bash
RECON_APP_NAME="Night Owl" recon --serve
```

Useful if you fork this or run it inside a team that would rather see its own
name on the console.

### The dashboard is loopback-only

The web dashboard binds to `127.0.0.1` and the listen address is **not
configurable**. A scanner answering on a campus or client network is itself an
exposure. If you need it from another machine, forward it over SSH:

```bash
ssh -L 8787:127.0.0.1:8787 you@thatmachine
```

### What never goes in the repository

`.gitignore` excludes these, and you should confirm it before every push:

```
config/scope.json     # names real targets and who authorized them
out/                  # raw scan results
reports/              # written findings
*.log
```

Only `config/scope.example.json`, which contains placeholder values, is tracked.
**A scope file is a client document.** It names hosts, an authorizing person, and a
date window; publishing one exposes the client and can breach the engagement
contract. The same is true of scan output, which names live hosts and open
services.

### Data handling

- Scan history is capped at 50 records in `out/scans/` and old records are pruned
  automatically. Findings that name open services are a liability to keep forever
  on a shared lab machine.
- Nothing is transmitted anywhere. There is no telemetry, no update check, and no
  external API call. Everything written stays on the machine that ran it.
- Reports are plain Markdown so you can read exactly what you are about to hand
  over before you hand it over.

### Before you publish this repository

1. `git status --ignored` and confirm `config/scope.json`, `out/`, and `reports/`
   are listed as ignored, not staged.
2. `git log -p | grep -iE "scope.json|in_scope"` and confirm no real scope file was
   ever committed. Deleting a file in a later commit does **not** remove it from
   history.
3. Confirm no real hostnames or client IPs appear in tests or examples. This
   repository uses RFC 5737 (`203.0.113.0/24`) documentation addresses and RFC 1918
   private ranges (`10.0.0.0/8`, `192.168.56.0/24`) for exactly this reason, plus
   `scanme.nmap.org`, the host the Nmap Project publishes for scan testing.

---

## Legal and ethical use

Port scanning, service enumeration, and HTTP probing of systems you do not own or
have written permission to test is a crime in most jurisdictions, including under
the US Computer Fraud and Abuse Act and California Penal Code 502. "I was only
scanning" is not a defense.

Use this tool only where you hold written authorization, and only within the scope
and dates that authorization grants. See [docs/WHITE-HAT-AGREEMENT.md](docs/WHITE-HAT-AGREEMENT.md)
for the rules of engagement this project is built around, and fill one out before
your first scan of any engagement.

The scope enforcement in this tool is a safety net against mistakes. It is not a
substitute for permission, and it does not make an unauthorized scan legal.

---

## Project layout

```
src/recon/
  scope.py       authorization boundary — the core of the design
  cli.py         command-line entry point
  webapp.py      loopback-only dashboard
  report.py      findings derivation and Markdown reports
  store.py       shared scan history for CLI and dashboard
  paths.py       where the scope file, history and reports live per platform
  output.py      terminal rendering
  modules/       the eight recon modules
config/          scope.example.json (tracked), scope.json (never tracked)
docs/            white hat agreement
tests/           42 tests, mostly covering scope enforcement and path resolution
```

## Testing

```bash
PYTHONPATH=src python3 -m pytest tests/ -q
```

The test suite concentrates on `scope.py`, because that is the file where a bug
means an unauthorized scan rather than a wrong answer. It covers exact and wildcard
matching, lookalike-domain rejection, CIDR ranges, exclusion precedence, the
engagement window in both states, and resolved-address re-checking.
