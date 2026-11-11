"""Unit tests for the code-attribution stage's image-independent logic.

The ioctl decoder and the COD-decision mapping are pure functions, so they are
tested here without an image. The end-to-end ELF/ghidra dispatch is exercised on the
real reference image (see the handoff doc's proof targets), not in unit tests.
"""

from sesurface.attribute import (Attribution, decode_ioctls, _expand_xperm,
                               _daemon_stem, _match_checks, writeback)
from sesurface.types import Decision, Finding, Gate, GateVerdict


def test_expand_xperm_ranges_and_singletons():
    assert _expand_xperm("ioctl 0x6201 0x6205-0x6209") == [
        0x6201, 0x6205, 0x6206, 0x6207, 0x6208, 0x6209]


def test_decode_binder_ioctls_names_every_command():
    xperms = ["ioctl 0x6201 0x6203 0x6205-0x6209 0x620b-0x620d 0x6210"]
    decoded = decode_ioctls(xperms)
    names = [name for _cmd, _h, name in decoded]
    assert "BINDER_WRITE_READ" in names            # 0x6201
    assert "BINDER_SET_CONTEXT_MGR" in names        # 0x6207
    assert "BINDER_ENABLE_ONEWAY_SPAM_DETECTION" in names   # 0x6210
    # all dispatched by the binder driver entry point
    assert all(h == "binder_ioctl" for _c, h, _n in decoded)
    assert not any(n.startswith("(cmd") for n in names)   # nothing left unnamed


def test_decode_unknown_ioctl_type_degrades_gracefully():
    # type 'z' (0x7a) is not in our tables -> decode by raw command, don't crash.
    decoded = decode_ioctls(["ioctl 0x7a01"])
    assert decoded[0][2].startswith("(cmd 0x7a01")


def test_daemon_stem_strips_role_suffix():
    assert _daemon_stem("/system/bin/audioserver") == "audio"
    assert _daemon_stem("/system/bin/cameraserver") == "camera"
    # too-short stems are rejected (avoids spurious lib matches).
    assert _daemon_stem("/system/bin/sh") == ""


def test_match_checks_finds_caller_check_symbols():
    syms = ["_ZN7android16recordingAllowedE", "_ZN7android13AppOpsManager6noteOpEi",
            "memcpy", "_ZN7android14IPCThreadState14getCallingUidEv"]
    hits = _match_checks(syms)
    assert any("recordingAllowed" in h for h in hits)
    assert any("getCallingUid" in h for h in hits)
    assert "memcpy" not in hits


def _finding(tclass="binder", setype="audioserver"):
    f = Finding(setype=setype, tclass=tclass, perms=frozenset({"call"}))
    f.gates[Gate.INCODE] = GateVerdict(Gate.INCODE, Decision.UNKNOWN)
    return f


def test_open_attribution_upgrades_cod_to_allow():
    f = _finding()
    attr = Attribution("audioserver", "binder", "open", handler="h", caller_check="none")
    assert attr.cod_decision() is Decision.ALLOW
    writeback(f, attr)
    assert f.gates[Gate.INCODE].decision is Decision.ALLOW
    assert f.gates[Gate.INCODE].detail["attribution"] == "open"


def test_gated_attribution_leaves_cod_unknown_but_explains():
    # A caller check exists but a runtime grant is unknowable statically: we must not
    # fabricate a DENY. The decision stays UNKNOWN; the evidence now explains why.
    f = _finding()
    attr = Attribution("audioserver", "binder", "gated", handler="h",
                       caller_check="found", checks=["android::recordingAllowed()"])
    assert attr.cod_decision() is None
    writeback(f, attr)
    assert f.gates[Gate.INCODE].decision is Decision.UNKNOWN
    assert f.gates[Gate.INCODE].detail["caller_check"] == "found"
    assert "attribution=gated" in f.gates[Gate.INCODE].evidence


def test_unresolved_never_upgrades_cod_to_allow():
    # The critical correctness property of fix B: "no binary scanned" must not be
    # reported as "no caller check". unresolved leaves the gate UNKNOWN, never ALLOW.
    f = _finding()
    attr = Attribution("pdx_channel_socket_type", "unix_stream_socket", "unresolved",
                       caller_check="unknown")
    assert attr.cod_decision() is None
    writeback(f, attr)
    assert f.gates[Gate.INCODE].decision is Decision.UNKNOWN
    assert f.gates[Gate.INCODE].detail["attribution"] == "unresolved"
    assert f.gates[Gate.INCODE].detail["caller_check"] == "unknown"


def test_open_requires_a_scanned_binary_distinct_from_unresolved():
    # open and unresolved are different verdicts: only open upgrades the gate.
    assert Attribution("x", "binder", "open").cod_decision() is Decision.ALLOW
    assert Attribution("x", "binder", "unresolved").cod_decision() is None


def test_aggregate_attribution_does_not_upgrade_cod():
    # A multi-member policy attribute (binderservicedomain, domain) is not one handler,
    # so it must not upgrade the gate to allow.
    f = _finding(setype="binderservicedomain")
    attr = Attribution("binderservicedomain", "binder", "aggregate",
                       caller_check="n/a")
    assert attr.cod_decision() is None
    writeback(f, attr)
    assert f.gates[Gate.INCODE].decision is Decision.UNKNOWN
    assert f.gates[Gate.INCODE].detail["attribution"] == "aggregate"


def test_resolution_status_flags_what_still_needs_analysis():
    # The audit ledger must separate "trust it" from "a human still has to look".
    assert Attribution("x", "binder", "gated", method="ghidra").resolution() == "decided"
    assert Attribution("x", "binder", "gated",
                       method="elf-dynsym").resolution() == "needs-review"
    assert Attribution("x", "binder", "open",
                       method="elf-dynsym").resolution() == "needs-review"
    assert Attribution("x", "chr_file", "kernel",
                       method="ioctl-decode").resolution() == "decided"
    assert Attribution("x", "hwservice_manager", "latent").resolution() == "decided"
    assert Attribution("x", "binder", "aggregate").resolution() == "needs-review"
    assert Attribution("x", "binder", "unresolved").resolution() == "unresolved"
    assert Attribution("x", "binder", "gated",
                       method="jadx-deferred").resolution() == "not-attempted"
    assert Attribution("x", "file", "skipped").resolution() == "n/a"


def test_kernel_attribution_does_not_touch_decision():
    f = _finding(tclass="chr_file", setype="binder_device")
    f.gates[Gate.INCODE] = GateVerdict(Gate.INCODE, Decision.NA)
    attr = Attribution("binder_device", "chr_file", "kernel", handler="binder_ioctl",
                       ioctls=["0x6201 BINDER_WRITE_READ (hot)"])
    assert attr.cod_decision() is None
    writeback(f, attr)
    assert f.gates[Gate.INCODE].decision is Decision.NA
    assert "ioctls=" in f.gates[Gate.INCODE].evidence
