"""Authorization boundary.

Every target passes through here before any module touches the network. A target
is permitted only when it matches an in-scope entry, matches no out-of-scope
entry, and the engagement window is currently open. Hostnames are additionally
resolved and every resulting address is re-checked against the exclusion list,
so a name that redirects onto an excluded host is still refused. Setting
"strict_resolution": true also requires each resolved address to be listed
in_scope, for engagements where the hosting addresses are known up front.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import pathlib
import socket
from dataclasses import dataclass, field
from typing import Iterable


class ScopeError(Exception):
    """Raised when a scope file is unusable."""


class OutOfScope(Exception):
    """Raised when a target is not authorized. Never catch this to continue."""


def _today() -> _dt.date:
    return _dt.date.today()


def _parse_entry(entry: str):
    """Return ('net', network) for an IP or CIDR, ('host', name) otherwise."""
    entry = entry.strip().lower().rstrip(".")
    if not entry:
        raise ScopeError("empty scope entry")
    try:
        return "net", ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return "host", entry



def missing_scope_help(wanted=None) -> str:
    """What to actually do about a missing scope file, on this machine.

    Printing a relative path is no help to someone who installed the command
    and is standing in their home directory, so name the real destination and
    the example to copy from.
    """
    from . import paths  # imported here to keep scope.py free of import cycles

    target = pathlib.Path(wanted) if wanted else paths.scope_path()
    example = paths.example_scope()
    lines = []
    if example:
        lines.append(f"Create one:  recon --init      (copies {example.name} to {target})")
    else:
        lines.append(f"Create {target} — see config/scope.example.json in the repository.")
    lines.append(f"Or point at one you already have:  --scope /path/to/scope.json")
    searched = [str(c) for c in paths.scope_candidates()]
    if searched:
        lines.append("Looked in: " + ", ".join(searched))
    return "\n".join(lines)

@dataclass
class Scope:
    engagement: str
    authorized_by: str
    valid_from: _dt.date
    valid_until: _dt.date
    in_scope: list = field(default_factory=list)
    out_of_scope: list = field(default_factory=list)
    max_concurrency: int = 20
    authorization_ref: str = ""
    strict_resolution: bool = False
    app_name: str = ""
    source_path: str = ""

    # ---------- loading ----------

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "Scope":
        p = pathlib.Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}\n{missing_scope_help(p)}")
        raw = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            try:
                import yaml  # optional
            except ImportError as exc:
                raise ScopeError(
                    "YAML scope files need PyYAML installed; use JSON instead."
                ) from exc
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)

        missing = [
            k for k in ("engagement", "authorized_by", "valid_from", "valid_until", "in_scope")
            if k not in data
        ]
        if missing:
            raise ScopeError(f"scope file is missing required keys: {', '.join(missing)}")
        if not data["in_scope"]:
            raise ScopeError("in_scope is empty — nothing is authorized")

        def _date(key):
            try:
                return _dt.date.fromisoformat(str(data[key]))
            except ValueError as exc:
                raise ScopeError(f"{key} must be YYYY-MM-DD, got {data[key]!r}") from exc

        return cls(
            engagement=str(data["engagement"]),
            authorized_by=str(data["authorized_by"]),
            authorization_ref=str(data.get("authorization_ref", "")),
            valid_from=_date("valid_from"),
            valid_until=_date("valid_until"),
            in_scope=[_parse_entry(e) for e in data["in_scope"]],
            out_of_scope=[_parse_entry(e) for e in data.get("out_of_scope", [])],
            max_concurrency=int(data.get("max_concurrency", 20)),
            strict_resolution=bool(data.get("strict_resolution", False)),
            app_name=str(data.get("app_name", "")),
            source_path=str(p),
        )

    # ---------- checks ----------

    def window_open(self, on: _dt.date | None = None) -> bool:
        on = on or _today()
        return self.valid_from <= on <= self.valid_until

    def _matches(self, rules, target: str) -> bool:
        target = target.strip().lower().rstrip(".")
        addr = None
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            pass

        for kind, value in rules:
            if kind == "net":
                if addr is not None and addr in value:
                    return True
            else:
                # exact host, or a subdomain of the authorized host
                if target == value or target.endswith("." + value):
                    return True
        return False

    def resolve(self, host: str) -> list:
        """Best-effort forward resolution.

        IPv4 addresses come first. Plenty of lab and campus networks resolve
        AAAA records but have no v6 route, and a scanner that silently picks the
        unreachable address reports every port as an error.
        """
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return []
        v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        return v4 + v6

    def check(self, target: str, *, resolve: bool = True) -> list:
        """Authorize a target or raise OutOfScope. Returns the resolved addresses."""
        on = _today()
        if not self.window_open(on):
            raise OutOfScope(
                f"engagement window is closed: authorized {self.valid_from} to "
                f"{self.valid_until}, today is {on}"
            )

        if self._matches(self.out_of_scope, target):
            raise OutOfScope(f"{target} is explicitly listed out of scope")

        if not self._matches(self.in_scope, target):
            raise OutOfScope(
                f"{target} is not in scope for '{self.engagement}'.\n"
                f"Authorized entries live in {self.source_path}."
            )

        addresses: list = []
        try:
            ipaddress.ip_address(target)
            addresses = [target]
        except ValueError:
            if resolve:
                addresses = self.resolve(target)
                if not addresses:
                    return []
                for a in addresses:
                    # An explicit exclusion always wins, however the name resolved.
                    if self._matches(self.out_of_scope, a):
                        raise OutOfScope(
                            f"{target} resolves to {a}, which is explicitly out of scope"
                        )
                    # Requiring the address itself to be listed is opt-in: most
                    # engagements authorize names without knowing the hosting IPs.
                    if self.strict_resolution and not self._matches(self.in_scope, a):
                        raise OutOfScope(
                            f"{target} resolves to {a}, which is outside the authorized ranges "
                            "and strict_resolution is on. Add the address to in_scope, or turn "
                            "strict_resolution off if the hosting IPs are not known up front."
                        )
        return addresses

    def filter(self, targets: Iterable[str]) -> tuple:
        """Split targets into (allowed, [(target, reason), ...])."""
        allowed, refused = [], []
        for t in targets:
            try:
                self.check(t)
                allowed.append(t)
            except OutOfScope as exc:
                refused.append((t, str(exc)))
        return allowed, refused

    def banner(self) -> str:
        ref = f" ({self.authorization_ref})" if self.authorization_ref else ""
        return (
            f"Engagement : {self.engagement}\n"
            f"Authorized : {self.authorized_by}{ref}\n"
            f"Window     : {self.valid_from} to {self.valid_until}"
            f"{'' if self.window_open() else '   *** CLOSED ***'}\n"
            f"Scope file : {self.source_path}"
        )
