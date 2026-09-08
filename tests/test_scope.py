import datetime as dt
import json

import pytest

from recon.scope import OutOfScope, Scope, ScopeError

BASE = {
    "engagement": "unit test",
    "authorized_by": "test harness",
    "valid_from": "2000-01-01",
    "valid_until": "2100-01-01",
    "in_scope": ["example.com", "10.0.0.0/24"],
    "out_of_scope": ["10.0.0.1", "secret.example.com"],
}


def write(tmp_path, **overrides):
    data = {**BASE, **overrides}
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(data))
    return Scope.load(p)


def test_exact_domain_allowed(tmp_path):
    s = write(tmp_path)
    assert s._matches(s.in_scope, "example.com")


def test_subdomain_allowed(tmp_path):
    s = write(tmp_path)
    assert s._matches(s.in_scope, "api.example.com")


def test_lookalike_domain_refused(tmp_path):
    """notexample.com must not match example.com."""
    s = write(tmp_path)
    assert not s._matches(s.in_scope, "notexample.com")


def test_ip_in_cidr_allowed(tmp_path):
    s = write(tmp_path)
    assert s._matches(s.in_scope, "10.0.0.55")


def test_ip_outside_cidr_refused(tmp_path):
    s = write(tmp_path)
    assert not s._matches(s.in_scope, "10.0.1.55")


def test_out_of_scope_beats_in_scope(tmp_path):
    s = write(tmp_path)
    with pytest.raises(OutOfScope, match="explicitly listed out of scope"):
        s.check("10.0.0.1", resolve=False)


def test_out_of_scope_subdomain_refused(tmp_path):
    s = write(tmp_path)
    with pytest.raises(OutOfScope):
        s.check("secret.example.com", resolve=False)


def test_unlisted_target_refused(tmp_path):
    s = write(tmp_path)
    with pytest.raises(OutOfScope, match="not in scope"):
        s.check("evil.test", resolve=False)


def test_expired_window_refuses_everything(tmp_path):
    s = write(tmp_path, valid_until="2000-01-02")
    with pytest.raises(OutOfScope, match="window is closed"):
        s.check("example.com", resolve=False)


def test_future_window_refuses_everything(tmp_path):
    future = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    s = write(tmp_path, valid_from=future, valid_until="2100-01-01")
    with pytest.raises(OutOfScope, match="window is closed"):
        s.check("example.com", resolve=False)


def test_empty_in_scope_rejected(tmp_path):
    with pytest.raises(ScopeError, match="nothing is authorized"):
        write(tmp_path, in_scope=[])


def test_missing_keys_rejected(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"engagement": "x"}))
    with pytest.raises(ScopeError, match="missing required keys"):
        Scope.load(p)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(ScopeError, match="not found"):
        Scope.load(tmp_path / "nope.json")


def test_resolved_address_outside_scope_refused_when_strict(tmp_path, monkeypatch):
    """With strict_resolution on, a name resolving off-scope is refused."""
    s = write(tmp_path, strict_resolution=True)
    monkeypatch.setattr(Scope, "resolve", lambda self, host: ["203.0.113.9"])
    with pytest.raises(OutOfScope, match="outside the authorized ranges"):
        s.check("api.example.com")


def test_resolved_address_outside_scope_allowed_by_default(tmp_path, monkeypatch):
    """Without strict_resolution, unknown hosting addresses are fine."""
    s = write(tmp_path)
    monkeypatch.setattr(Scope, "resolve", lambda self, host: ["203.0.113.9"])
    assert s.check("api.example.com") == ["203.0.113.9"]


def test_excluded_resolved_address_always_refused(tmp_path, monkeypatch):
    """An exclusion holds even with strict_resolution off."""
    s = write(tmp_path, out_of_scope=["203.0.113.9"])
    monkeypatch.setattr(Scope, "resolve", lambda self, host: ["203.0.113.9"])
    with pytest.raises(OutOfScope, match="explicitly out of scope"):
        s.check("api.example.com")


def test_resolved_address_inside_scope_allowed(tmp_path, monkeypatch):
    s = write(tmp_path, in_scope=["example.com", "203.0.113.0/24"])
    monkeypatch.setattr(Scope, "resolve", lambda self, host: ["203.0.113.9"])
    assert s.check("api.example.com") == ["203.0.113.9"]


def test_filter_splits_allowed_and_refused(tmp_path):
    s = write(tmp_path)
    allowed, refused = s.filter(["10.0.0.5", "10.0.0.1", "evil.test"])
    assert allowed == ["10.0.0.5"]
    assert [r[0] for r in refused] == ["10.0.0.1", "evil.test"]


def test_case_and_trailing_dot_normalised(tmp_path):
    s = write(tmp_path)
    assert s._matches(s.in_scope, "API.Example.COM.")


# --- report findings ---------------------------------------------------

def test_findings_flag_notable_ports():
    from recon.report import derive_findings
    f = derive_findings({"ports": {"open": [{"port": 6379, "service": "redis", "rtt_ms": 1}]}})
    assert any("redis" in x["title"] for x in f)
    assert f[0]["severity"] == "medium"


def test_findings_flag_missing_headers():
    from recon.report import derive_findings
    f = derive_findings({"http": {"results": {"https": {
        "reachable": True, "security": {"missing": ["content-security-policy"],
                                        "present": {}, "version_disclosure": {}}}}}})
    assert any("Security headers absent" in x["title"] for x in f)


def test_findings_ordered_by_severity():
    from recon.report import derive_findings
    f = derive_findings({
        "ports": {"open": [{"port": 6379, "service": "redis", "rtt_ms": 1},
                           {"port": 3306, "service": "mysql", "rtt_ms": 1}]},
    })
    sevs = [x["severity"] for x in f]
    assert sevs == sorted(sevs, key=lambda s: {"medium": 0, "low": 1, "informational": 2}[s])


def test_empty_results_produce_no_findings():
    from recon.report import derive_findings
    assert derive_findings({}) == []


def test_report_renders_without_findings():
    from recon.report import build
    md = build({"target": "x", "results": {}, "modules": [], "id": "abc"})
    assert "Nothing notable surfaced" in md
    assert md.startswith("# Reconnaissance — x")
