"""Where the scope file, scan history, and reports live on this machine.

Every path used to be written relative to the current directory, which meant
the tool only worked when you happened to be standing in the checkout. After
`pip install -e .` the `recon` command is on your PATH everywhere, so that was
a bug: running it from your home directory reported the scope file missing.

The rule now is:

1. An explicit path always wins — the `--scope` flag, or `RECON_SCOPE` /
   `RECON_HOME` in the environment.
2. Otherwise, if you are standing anywhere inside a checkout, the checkout is
   used. This keeps the README's `git clone && cd && python3 -m recon` flow
   working, and now it works from subdirectories too.
3. Otherwise, per-user directories under the platform's normal location, so an
   installed copy writes somewhere predictable instead of scattering `out/`
   folders wherever you happened to be.

Nothing here is shared between users and nothing is world-readable by design;
scan output names live hosts, so it belongs in the running user's own space.
"""

from __future__ import annotations

import os
import pathlib

APP_DIRNAME = "scout-up"
DEFAULT_APP_NAME = "Scout Up"

#: The file whose presence marks a checkout. It is tracked in git and a
#: configured install never has one, which is what makes it a reliable marker.
_ROOT_MARKER = pathlib.Path("config") / "scope.example.json"


def _env_path(name: str):
    raw = os.environ.get(name)
    if not raw or not raw.strip():
        return None
    return pathlib.Path(raw).expanduser()


def project_root(start=None):
    """The checkout containing `start`, or None if we are outside one."""
    here = pathlib.Path(start or pathlib.Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / _ROOT_MARKER).is_file():
            return candidate
    return None


def _user_dir(env_var: str, fallback: str) -> pathlib.Path:
    """A per-user directory, following whatever convention this OS uses."""
    if os.name == "nt":
        base = _env_path("LOCALAPPDATA") or pathlib.Path.home() / "AppData" / "Local"
    else:
        base = _env_path(env_var) or pathlib.Path.home() / fallback
    return base / APP_DIRNAME


def data_home() -> pathlib.Path:
    """Base directory for things the tool writes: scan history and reports."""
    override = _env_path("RECON_HOME")
    if override:
        return override
    root = project_root()
    if root:
        return root
    return _user_dir("XDG_DATA_HOME", ".local/share")


def config_home() -> pathlib.Path:
    """Base directory for the scope file when there is no checkout."""
    override = _env_path("RECON_HOME")
    if override:
        return override
    return _user_dir("XDG_CONFIG_HOME", ".config")


def scope_candidates() -> list:
    """Every path a scope file is looked for, in order. Used in errors too."""
    found = []
    explicit = _env_path("RECON_SCOPE")
    if explicit:
        found.append(explicit)
    root = project_root()
    if root:
        found.append(root / "config" / "scope.json")
    found.append(config_home() / "scope.json")
    return found


def scope_path() -> pathlib.Path:
    """The scope file to load: the first candidate that exists.

    When none exist we still return the first candidate, so the error names the
    path you most likely meant to create rather than the last one checked.
    """
    candidates = scope_candidates()
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def example_scope() -> pathlib.Path | None:
    """The shipped example, wherever this copy was installed from."""
    root = project_root()
    if root and (root / _ROOT_MARKER).is_file():
        return root / _ROOT_MARKER
    packaged = pathlib.Path(__file__).parent / "data" / "scope.example.json"
    return packaged if packaged.is_file() else None


def history_dir() -> pathlib.Path:
    return data_home() / "out" / "scans"


def report_dir() -> pathlib.Path:
    return data_home() / "reports"


def app_name(scope=None) -> str:
    """The name shown in the dashboard.

    A fork or an internal deployment usually wants its own name on the page, so
    this is configurable two ways and hardcoded in neither: `RECON_APP_NAME` in
    the environment, or `app_name` in the scope file.
    """
    env = os.environ.get("RECON_APP_NAME")
    if env and env.strip():
        return env.strip()
    if scope is not None:
        named = getattr(scope, "app_name", "")
        if named:
            return named
    return DEFAULT_APP_NAME
