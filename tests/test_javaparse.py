"""Unit tests for the decompiled-Java parser (image-independent)."""

from sesurface import javaparse as jp


def test_strip_comments():
    src = "a // line\nb /* block\nstill */ c"
    out = jp.strip_comments(src)
    assert "line" not in out
    assert "block" not in out
    assert "a" in out and "b" in out and "c" in out


def test_find_classes_nested_and_extends():
    src = """
    public final class FooService extends SystemService {
        static final int X = 1;
        public static class Stub extends android.os.Binder implements IFoo {
            public void doThing() { }
        }
    }
    """
    classes = {c.name: c for c in jp.find_classes(src)}
    assert "FooService" in classes and "Stub" in classes
    assert classes["FooService"].extends == "SystemService"
    assert classes["Stub"].extends.endswith(".Binder")
    assert "IFoo" in classes["Stub"].implements


def test_find_methods_top_level_only():
    body = """
        public void outer(int a) {
            if (a > 0) { helper(); }
        }
        class Inner { public void shouldNotCount() { } }
        public int second() { return 2; }
    """
    names = {m.name for m in jp.find_methods(body)}
    assert "outer" in names and "second" in names
    assert "shouldNotCount" not in names   # nested-class method excluded
    # control keywords inside a body are not methods
    assert "if" not in names


def test_transaction_handlers_picks_last_non_boilerplate_call():
    on_transact = """
        switch (code) {
            case 1:
                String s = data.readString();
                int n = data.readInt();
                data.enforceNoDataAvail();
                createBackingImage(s, n);
                reply.writeNoException();
                return true;
            case 2:
                boolean r = backingImageExists(data.readString());
                reply.writeBoolean(r);
                return true;
        }
    """
    handlers = jp.transaction_handlers(on_transact)
    assert handlers["1"] == "createBackingImage"
    assert handlers["2"] == "backingImageExists"


def test_transaction_constants():
    src = """
        static final int TRANSACTION_enableCarMode = 1;
        static final int TRANSACTION_getNightMode = (IBinder.FIRST_CALL_TRANSACTION + 5);
        static final int NOT_A_TXN = 9;
    """
    consts = jp.transaction_constants(src)
    assert consts["TRANSACTION_enableCarMode"] == 1
    assert consts["TRANSACTION_getNightMode"] == 5
    assert "NOT_A_TXN" not in consts


def test_find_checks_direct_and_permission():
    body = 'getContext().enforceCallingPermission("android.permission.FOO", "m");'
    ev = jp.find_checks(body)
    assert "enforceCallingPermission" in ev.checks
    assert "android.permission.FOO" in ev.permissions


def test_find_checks_uid_compare_vs_bare_read():
    gated = "if (Binder.getCallingUid() != 1000) throw new SecurityException();"
    assert jp.find_checks(gated).checks       # uid-compare detected
    bare = "int uid = getCallingUid(); log(uid);"
    assert not jp.find_checks(bare).checks     # a bare read is not a gate


def test_find_checks_annotation():
    ev = jp.find_checks("doStuff();", annotations=("EnforcePermission",))
    assert "EnforcePermission" in ev.annotations


def test_callees_filters_boilerplate():
    body = "data.readInt(); enforceFoo(); writeNoException(); doReal();"
    c = jp.callees(body)
    assert "enforceFoo" in c and "doReal" in c
    assert "readInt" not in c and "writeNoException" not in c
