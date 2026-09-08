"""Hop parsing.

The parser matched GNU traceroute's layout only. Against `tracepath`, which is
what is actually installed on a lot of machines, every hop was dropped and the
module still reported `available: true` with an empty list — a wrong answer that
looked like a successful run. These lock both layouts in.
"""

import pytest

from recon.modules import traceroute

GNU = """traceroute to scanme.nmap.org (45.33.32.156), 20 hops max
 1  192.168.4.1  1.952 ms
 2  47.146.128.1  6.989 ms
 3  *
 4  45.33.32.156  149.866 ms
"""

TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.4.1                                           1.952ms
 1:  192.168.4.1                                           1.807ms
 2:  47.146.128.1                                          6.989ms
 3:  74.40.1.230                                          10.330ms asymm  6
 4:  no reply
 5:  45.33.32.156                                         54.800ms reached
     Resume: pmtu 1500
"""


def _parse(monkeypatch, stdout, binary="tracepath"):
    class Done:
        returncode = 0

    Done.stdout = stdout
    Done.stderr = ""

    monkeypatch.setattr(traceroute, "_pick_binary", lambda: (binary, ["-n", "-m"]))
    monkeypatch.setattr(traceroute.subprocess, "run", lambda *a, **k: Done)

    class Scope:
        def check(self, target):
            return ["45.33.32.156"]

    return traceroute.run("scanme.nmap.org", Scope(), {})


def test_tracepath_hops_are_parsed(monkeypatch):
    """The regression: colon-suffixed hop numbers used to match nothing."""
    out = _parse(monkeypatch, TRACEPATH)
    assert out["hop_count"] == 5
    assert [h["hop"] for h in out["hops"]] == [1, 2, 3, 4, 5]
    assert out["hops"][0]["address"] == "192.168.4.1"
    assert out["hops"][-1]["address"] == "45.33.32.156"


def test_gnu_traceroute_still_parses(monkeypatch):
    out = _parse(monkeypatch, GNU, binary="traceroute")
    assert [h["hop"] for h in out["hops"]] == [1, 2, 3, 4]
    assert out["hops"][0]["address"] == "192.168.4.1"


@pytest.mark.parametrize("stdout,expected", [(TRACEPATH, 1), (GNU, 1)])
def test_unanswered_hops_are_counted_not_dropped(monkeypatch, stdout, expected):
    """A silent hop is information; it must survive as a hop with no address."""
    out = _parse(monkeypatch, stdout,
                 binary="tracepath" if stdout is TRACEPATH else "traceroute")
    assert out["silent_hops"] == expected
    silent = [h for h in out["hops"] if not h["responded"]]
    assert silent and all(h["address"] is None for h in silent)


def test_tracepath_mtu_probe_line_is_not_a_hop(monkeypatch):
    """`1?: [LOCALHOST]` is MTU discovery, not a router on the path."""
    out = _parse(monkeypatch, TRACEPATH)
    assert all("LOCALHOST" not in h["detail"] for h in out["hops"])


def test_repeated_probes_collapse_to_one_hop(monkeypatch):
    """tracepath probes hop 1 twice; it is still one hop."""
    out = _parse(monkeypatch, TRACEPATH)
    assert [h["hop"] for h in out["hops"]].count(1) == 1


def test_missing_binary_is_reported_not_crashed(monkeypatch):
    monkeypatch.setattr(traceroute, "_pick_binary", lambda: (None, None))

    class Scope:
        def check(self, target):
            return ["45.33.32.156"]

    out = traceroute.run("scanme.nmap.org", Scope(), {})
    assert out["available"] is False
    assert "note" in out
