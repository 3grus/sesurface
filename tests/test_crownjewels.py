"""Mechanism tests for the crown-jewels preset (the setools-free parts).

The holder enumeration needs a real policy; the reach-annotation logic and the
jewel inventory do not, so those are covered here.
"""

from __future__ import annotations

from types import SimpleNamespace

from sesurface import crownjewels
from sesurface.crownjewels import CROWN_JEWELS, JewelHolder, _reach_label, _gate_summary
from sesurface.types import Gate, GateVerdict, Decision


def test_jewel_inventory_covers_the_three_routes():
    names = {j.name for j in CROWN_JEWELS}
    # selinuxfs toggles (file route)
    assert "selinux enforce toggle" in names
    assert "selinux policy reload" in names
    # the backing security permissions
    assert "security:setenforce" in names
    assert "security:load_policy" in names
    # kernel / MAC capabilities
    assert "capability:sys_module" in names
    assert "capability2:mac_admin" in names
    kinds = {j.kind for j in CROWN_JEWELS}
    assert kinds == {"path", "class", "capability", "capability2"}


def test_reach_label_precedence_self_over_becomes_over_attacks():
    selfset = frozenset({"untrusted_app"})
    becomes = frozenset({"hal_foo", "vendor_init"})
    attacks = frozenset({"system_server"})
    assert _reach_label("untrusted_app", selfset, becomes, attacks) == "self"
    assert _reach_label("vendor_init", selfset, becomes, attacks) == "BECOMES"
    assert _reach_label("system_server", selfset, becomes, attacks) == "ATTACKS"
    assert _reach_label("init", selfset, becomes, attacks) == ""


def test_holders_sort_reachable_first():
    jewel = CROWN_JEWELS[0]
    res = crownjewels.JewelResult(jewel=jewel, resolved="selinuxfs via genfscon")
    res.holders = [
        JewelHolder("zzz_unreached", reach=""),
        JewelHolder("vendor_init", reach="BECOMES"),
        JewelHolder("aaa_unreached", reach=""),
    ]
    res.holders.sort(key=lambda h: (0 if h.reachable else 1, h.domain))
    assert [h.domain for h in res.holders] == [
        "vendor_init", "aaa_unreached", "zzz_unreached"]


def test_gate_summary_reports_dac_and_mls():
    t = SimpleNamespace(gates={
        Gate.MLS: GateVerdict(Gate.MLS, Decision.NA, ""),
        Gate.DAC: GateVerdict(Gate.DAC, Decision.DENY, ""),
    })
    s = _gate_summary(t)
    assert "MLS=n/a" in s
    assert "DAC=deny" in s
