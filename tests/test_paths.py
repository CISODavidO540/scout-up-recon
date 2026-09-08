"""Path resolution.

These cover the failure that made the tool look broken on any machine but the
one it was written on: every path used to be relative to the current directory,
so an installed copy run from anywhere else could not find its scope file.
"""

import json

import pytest

from recon import paths


@pytest.fixture
def checkout(tmp_path):
    """A directory that looks like a checkout, with a nested subdirectory."""
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scope.example.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src" / "recon").mkdir(parents=True)
    return tmp_path


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("RECON_HOME", "RECON_SCOPE", "RECON_APP_NAME",
                "XDG_DATA_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(var, raising=False)


def test_project_root_found_from_a_subdirectory(checkout, monkeypatch):
    monkeypatch.chdir(checkout / "src" / "recon")
    assert paths.project_root() == checkout.resolve()


def test_project_root_is_none_outside_a_checkout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert paths.project_root() is None


def test_checkout_keeps_its_own_scope_and_output(checkout, monkeypatch):
    monkeypatch.chdir(checkout / "src")
    assert paths.scope_path() == checkout.resolve() / "config" / "scope.json"
    assert paths.history_dir() == checkout.resolve() / "out" / "scans"
    assert paths.report_dir() == checkout.resolve() / "reports"


def test_installed_copy_uses_per_user_directories(tmp_path, monkeypatch):
    """The case that used to fail outright: no checkout anywhere above us."""
    home = tmp_path / "home"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))

    assert paths.scope_path() == home / ".config" / "scout-up" / "scope.json"
    assert paths.history_dir() == home / ".local" / "share" / "scout-up" / "out" / "scans"


def test_recon_home_overrides_a_checkout(checkout, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("RECON_HOME", str(elsewhere))
    assert paths.history_dir() == elsewhere / "out" / "scans"
    assert paths.report_dir() == elsewhere / "reports"


def test_recon_scope_wins_over_everything(checkout, tmp_path, monkeypatch):
    explicit = tmp_path / "engagement.json"
    explicit.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("RECON_SCOPE", str(explicit))
    assert paths.scope_path() == explicit
    assert paths.scope_candidates()[0] == explicit


def test_missing_scope_still_names_a_path_to_create(tmp_path, monkeypatch):
    """With nothing on disk we must still suggest somewhere, not crash."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    assert paths.scope_path().name == "scope.json"


def test_app_name_defaults_then_yields_to_scope_then_to_env(monkeypatch):
    class FakeScope:
        app_name = ""

    assert paths.app_name(FakeScope()) == paths.DEFAULT_APP_NAME

    FakeScope.app_name = "Night Owl"
    assert paths.app_name(FakeScope()) == "Night Owl"

    monkeypatch.setenv("RECON_APP_NAME", "Blue Team Console")
    assert paths.app_name(FakeScope()) == "Blue Team Console"


def test_blank_env_values_are_ignored(checkout, monkeypatch):
    """An exported-but-empty variable should not blank out the real path."""
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("RECON_HOME", "   ")
    monkeypatch.setenv("RECON_APP_NAME", "")
    assert paths.history_dir() == checkout.resolve() / "out" / "scans"
    assert paths.app_name(None) == paths.DEFAULT_APP_NAME


def test_scope_file_can_carry_a_display_name(tmp_path):
    """app_name travels with the engagement, so a fork needs no code change."""
    from recon.scope import Scope

    f = tmp_path / "scope.json"
    f.write_text(json.dumps({
        "engagement": "Example", "authorized_by": "Someone",
        "valid_from": "2026-01-01", "valid_until": "2026-12-31",
        "in_scope": ["example.com"], "app_name": "Night Owl",
    }), encoding="utf-8")

    assert paths.app_name(Scope.load(f)) == "Night Owl"
