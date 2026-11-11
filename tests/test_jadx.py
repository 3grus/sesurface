"""Tests for the framework (jadx) COD analyzer, using tiny Java fixtures.

Image- and jadx-independent: we hand-write a minimal decompiled tree (a framework
interface with TRANSACTION_ constants, plus a services.jar-style impl file) and assert
the per-transaction verdicts and the jadx-missing degradation.
"""

import os

import pytest

from sesurface import jadx


# A framework.jar-style AIDL interface: the authoritative transaction set + codes.
_IFACE = """
package android.app;
public interface IFooManager extends android.os.IInterface {
    public static abstract class Stub extends android.os.Binder implements IFooManager {
        static final int TRANSACTION_openThing = 1;
        static final int TRANSACTION_readThing = 2;
        static final int TRANSACTION_viaHelper = 3;
        static final int TRANSACTION_viaUnknown = 4;
        static final int TRANSACTION_annotated = 5;
        static final int TRANSACTION_missing = 6;
    }
}
"""

# A services.jar-style impl: registers the service and overrides the handlers. The
# enforce helper lives on the OUTER class (one-hop across the nested impl boundary).
_IMPL = """
package com.android.server;
public class FooManagerService extends SystemService {
    public final android.app.IFooManager.Stub mService = new BinderService();

    public void onStart() {
        publishBinderService("foo", this.mService);
    }

    private void enforceFooPermission() {
        getContext().enforceCallingPermission("android.permission.MANAGE_FOO", "foo");
    }

    class BinderService extends android.app.IFooManager.Stub {
        public void openThing(int a) {
            getContext().enforceCallingOrSelfPermission("android.permission.OPEN", "o");
        }
        public int readThing() {
            return mState;   // no caller check, no helper -> ungated (actionable)
        }
        public void viaHelper(int a) {
            enforceFooPermission();   // one-hop enforce helper -> gated
        }
        public void viaUnknown(int a) {
            checkSomethingExternal(a);   // helper not in this file -> needs-review
        }
        public void annotated(int a) {
        }
    }
}
"""


def _tree(tmp_path):
    """Write the fixture into a services/ + framework/ decompiled-tree pair."""
    svc = tmp_path / "services" / "sources"
    fw = tmp_path / "framework" / "sources"
    (svc / "com" / "android" / "server").mkdir(parents=True)
    (fw / "android" / "app").mkdir(parents=True)
    (svc / "com" / "android" / "server" / "FooManagerService.java").write_text(_IMPL)
    (fw / "android" / "app" / "IFooManager.java").write_text(_IFACE)
    return str(svc), str(fw)


def test_analyze_service_per_transaction(tmp_path):
    svc, fw = _tree(tmp_path)
    fa = jadx.FrameworkAnalyzer(svc, fw)
    cod = fa.analyze_service("foo")
    assert cod is not None
    assert cod.service == "foo"
    assert cod.interface == "android.app.IFooManager"
    by = {t.method: t for t in cod.transactions}

    assert by["openThing"].status == "gated" and by["openThing"].code == 1
    assert "OPEN" in by["openThing"].permissions

    assert by["readThing"].status == "ungated"        # actionable, decided

    assert by["viaHelper"].status == "gated"          # one-hop enforce* helper
    assert by["viaHelper"].via.startswith("helper:")

    assert by["viaUnknown"].status == "needs-review"  # unresolved enforce-looking call

    # The interface declares a transaction the impl does not override.
    assert by["missing"].status == "not-attempted" and by["missing"].code == 6


def test_verdict_open_when_any_ungated(tmp_path):
    svc, fw = _tree(tmp_path)
    cod = jadx.FrameworkAnalyzer(svc, fw).analyze_service("foo")
    assert cod.verdict() == "open"      # readThing is ungated
    c = cod.counts()
    assert c["ungated"] >= 1 and c["gated"] >= 2


def test_unknown_service_returns_none(tmp_path):
    svc, fw = _tree(tmp_path)
    assert jadx.FrameworkAnalyzer(svc, fw).analyze_service("nope") is None


def test_fallback_without_framework_marks_approximate(tmp_path):
    svc, _fw = _tree(tmp_path)
    cod = jadx.FrameworkAnalyzer(svc, None).analyze_service("foo")
    assert cod is not None
    assert "approximated" in cod.note     # transaction set is an upper bound


def test_decompile_jar_raises_when_jadx_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(jadx, "resolve_jadx", lambda: None)
    monkeypatch.delenv("SESURFACE_JADX", raising=False)
    jar = tmp_path / "x.jar"
    jar.write_bytes(b"PK\x03\x04dummy")
    with pytest.raises(jadx.JadxError):
        jadx.decompile_jar(str(jar), str(tmp_path / "cache"))


def test_interface_transactions_reads_codes(tmp_path):
    _svc, fw = _tree(tmp_path)
    fa = jadx.FrameworkAnalyzer(str(tmp_path / "services" / "sources"), fw)
    txns = fa.interface_transactions("android.app.IFooManager")
    assert txns == {"openThing": 1, "readThing": 2, "viaHelper": 3,
                    "viaUnknown": 4, "annotated": 5, "missing": 6}
    assert fa.interface_transactions("android.app.INotThere") is None
