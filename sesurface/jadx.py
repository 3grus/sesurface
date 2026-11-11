"""Stage H, jadx half: resolve the in-code (COD) gate for framework services.

The single `system_server:binder` finding sits in front of the *entire* Android
framework service surface: every AIDL transaction an app can send is dispatched by
`system_server`, and whether a given transaction is reachable is enforced **in Java
code** (`enforceCallingPermission`, `checkPermission`, AppOps, UID checks) that
SELinux cannot see. This module reads that code.

What is and is not in `services.jar`
------------------------------------
`services.jar` holds the service **implementations** (`FooManagerService extends
IFoo.Stub`, overriding the handler methods and containing the caller checks). The
AIDL **interface** (`IFoo.Stub.onTransact` with the numeric `switch (code)` and the
`TRANSACTION_*` constants) lives in `framework.jar`, which is *not* indexed here.

So we enumerate a service's **transactions as its interface methods** -- which is the
exact semantic unit (one AIDL method == one transaction code) -- and decide, per
method, whether a caller check gates it. The integer transaction code is a cosmetic
label we can only supply when `framework.jar` is also decompiled (optional, not
required for the verdict). This is stated in every result so nothing is overclaimed.

Honesty discipline (per the handoff)
------------------------------------
Each transaction gets a status, never a silent guess:
  * ``gated``         -- a caller check is on the method's entry path (direct, a
                         one-hop ``enforce*`` helper, or an ``@EnforcePermission``
                         annotation). Decided.
  * ``ungated``       -- the method body is self-contained and enforces nothing: the
                         actionable, confirmed-reachable surface. Decided.
  * ``needs-review``  -- a check *might* exist behind a callee we could not resolve,
                         or the gate depends on a runtime grant: worst-case treated as
                         reachable, flagged for a human.
  * ``not-attempted`` -- the impl method could not be located/parsed.

When unsure we default to the worst case for the attacker (reachable) AND flag
``needs-review`` -- never downgrade an uncertain case to a confident "gated".

Untrusted-data hygiene: the firmware jar is untrusted. We decompile it in an isolated
scratch dir, pass paths as arguments, read the output as text, and never execute it.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from . import javaparse as jp


# --------------------------------------------------------------------------- #
# jadx discovery + invocation
# --------------------------------------------------------------------------- #

class JadxError(RuntimeError):
    """jadx is required for this stage but is missing or failed."""


# Mirror doctor.py's resolution: $SESURFACE_JADX (the binary), then well-known dirs,
# then PATH.
_JADX_CANDIDATES = ("~/jadx/bin/jadx", "/opt/jadx/bin/jadx")


def resolve_jadx() -> Optional[str]:
    """Absolute path to a usable jadx binary, or None if none is found."""
    env = os.environ.get("SESURFACE_JADX")
    if env:
        p = os.path.expanduser(env)
        if os.path.exists(p):
            return p
    for c in _JADX_CANDIDATES:
        p = os.path.expanduser(c)
        if os.path.exists(p):
            return p
    found = shutil.which("jadx")
    return found


def _jar_fingerprint(jar_path: str) -> str:
    """A content fingerprint for the jar, to key the decompile cache."""
    h = hashlib.sha256()
    try:
        with open(jar_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return "nojar"
    return h.hexdigest()[:16]


def decompile_jar(jar_path: str, cache_root: str,
                  jadx_bin: Optional[str] = None,
                  timeout: int = 1800) -> str:
    """Decompile `jar_path` to Java with jadx, caching by the jar's content hash.

    Returns the path to the decompiled `sources/` tree. Re-runs are a no-op once the
    cache for that jar content exists, so the slow jadx pass happens at most once per
    image. Raises `JadxError` if jadx is unavailable or produces no output.
    """
    jadx = jadx_bin or resolve_jadx()
    if not jadx:
        raise JadxError(
            "jadx not found: set SESURFACE_JADX or install to ~/jadx/bin/jadx. "
            "The framework (system_server) COD gate cannot be read without it "
            "(run `sesurface doctor`).")

    fp = _jar_fingerprint(jar_path)
    out_dir = os.path.join(cache_root, f"jadx-{fp}")
    sources = os.path.join(out_dir, "sources")
    done = os.path.join(out_dir, ".done")
    if os.path.exists(done) and os.path.isdir(sources):
        return sources

    os.makedirs(out_dir, exist_ok=True)
    try:
        proc = subprocess.run(
            [jadx, "-j", str(os.cpu_count() or 4), "--no-res", "--no-imports",
             "-d", out_dir, jar_path],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise JadxError(f"jadx timed out after {timeout}s on {jar_path}") from e
    except OSError as e:
        raise JadxError(f"could not run jadx ({jadx}): {e}") from e

    # jadx exits non-zero when *some* classes fail, yet still emits usable sources for
    # the rest. Treat "a sources tree with .java files" as success and record it.
    if not os.path.isdir(sources) or not _has_java(sources):
        raise JadxError(
            f"jadx produced no Java sources for {jar_path} "
            f"(exit {proc.returncode}): {proc.stderr[-400:]}")
    with open(done, "w") as f:
        f.write(fp)
    return sources


def _has_java(tree: str) -> bool:
    for _root, _dirs, files in os.walk(tree):
        if any(name.endswith(".java") for name in files):
            return True
    return False


# --------------------------------------------------------------------------- #
# Per-service / per-transaction results
# --------------------------------------------------------------------------- #

@dataclass
class Transaction:
    """One AIDL transaction (== one interface method) and its gate verdict."""
    method: str
    status: str                         # gated | ungated | needs-review | not-attempted
    via: str = ""                       # direct | helper:<name> | annotation | unresolved
    checks: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    code: Optional[int] = None          # numeric code if framework.jar was joined
    note: str = ""


# Impl methods that are Binder/ServiceManager infrastructure, not AIDL transactions.
_NON_TRANSACTION = frozenset({
    "onTransact", "asBinder", "asInterface", "onShellCommand", "dump", "dumpsys",
    "getInterfaceVersion", "getInterfaceHash", "getInterfaceDescriptor",
    "queryLocalInterface", "attachInterface", "newArray", "describeContents",
    "writeToParcel", "hashCode", "equals", "toString", "finalize",
})


@dataclass
class ServiceCOD:
    """The COD verdict for one framework service: a ledger of its transactions."""
    service: str                        # registered ServiceManager name ("" if unknown)
    interface: str                      # AIDL interface the impl extends
    impl_class: str
    impl_file: str
    transactions: list[Transaction] = field(default_factory=list)
    note: str = ""

    def counts(self) -> dict[str, int]:
        c = {"gated": 0, "ungated": 0, "needs-review": 0, "not-attempted": 0}
        for t in self.transactions:
            c[t.status] = c.get(t.status, 0) + 1
        return c

    def ungated(self) -> list[Transaction]:
        return [t for t in self.transactions if t.status == "ungated"]

    def verdict(self) -> str:
        """Fold the per-transaction statuses into an attribution verdict.

        Any decided-ungated transaction means a confirmed-reachable code exists, so
        the service surface is *open*. Otherwise, if every transaction is gated it is
        *gated* (explained). A service we could not read at all is *unresolved*.
        """
        c = self.counts()
        decided = c["gated"] + c["ungated"]
        if decided == 0 and c["not-attempted"]:
            return "unresolved"
        if c["ungated"]:
            return "open"
        if c["gated"]:
            return "gated"
        return "unresolved"


# --------------------------------------------------------------------------- #
# Framework analyzer: index the decompiled tree, analyse a service
# --------------------------------------------------------------------------- #

_STUB_EXTENDS = re.compile(r"\.Stub$")
_REGISTER = re.compile(
    r"(?:publishBinderService|ServiceManager\.addService|addService)\s*\(\s*"
    r'"(?P<name>[\w./-]+)"\s*,\s*(?P<impl>[\w.$()]+)?')

# Names that look like a real permission-enforcing helper (one-hop decided): an
# enforce*/check*/assert*/require* method, or an `*Allowed()` gate helper (the
# convention the native side keys on too, e.g. recordingAllowed(), settingsAllowed()).
_ENFORCE_HELPER = re.compile(
    r"^(?:enforce|check|assert|require)\w*|\w*Allowed$", re.IGNORECASE)


class FrameworkAnalyzer:
    """Analyse framework-service COD against a decompiled services.jar tree.

    Built once per image (the decompile is cached). Indexes service registrations
    and impl classes lazily, then answers:
      * `analyze_service(name)`  -> one ServiceCOD (for a service_manager finding)
      * `analyze_all()`          -> every system_server-hosted service (the aggregate
                                    behind the single `system_server:binder` finding)
    """

    def __init__(self, sources_dir: str, framework_dir: Optional[str] = None):
        self._src = sources_dir
        # Optional decompiled framework.jar: supplies the authoritative transaction
        # set (and numeric codes) per AIDL interface, which services.jar lacks.
        self._fw = framework_dir
        self._files: Optional[list[str]] = None
        self._registry: Optional[dict[str, tuple[str, str]]] = None  # name->(file, impl)
        self._iface_cache: dict[str, Optional[dict[str, int]]] = {}

    # ---- tree plumbing --------------------------------------------------- #

    def _java_files(self) -> list[str]:
        if self._files is None:
            out: list[str] = []
            for root, _dirs, files in os.walk(self._src):
                for nm in files:
                    if nm.endswith(".java"):
                        out.append(os.path.join(root, nm))
            self._files = out
        return self._files

    @staticmethod
    def _read(path: str) -> str:
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    # ---- authoritative transaction set (from framework.jar) --------------- #

    def interface_transactions(self, fqname: str) -> Optional[dict[str, int]]:
        """`{method: code}` for an AIDL interface, from framework.jar's Stub.

        The `TRANSACTION_<method> = N` constants in the interface's generated Stub
        are the ground truth for *which* methods are transactions and their codes --
        the thing services.jar (impls only) cannot tell us. Returns None when
        framework.jar was not supplied or the interface is not in it (e.g. an APEX
        javalib service), so the caller can fall back and say so.
        """
        if not self._fw or not fqname:
            return None
        if fqname in self._iface_cache:
            return self._iface_cache[fqname]
        rel = fqname.replace(".", "/") + ".java"
        path = os.path.join(self._fw, rel)
        result: Optional[dict[str, int]] = None
        if os.path.exists(path):
            consts = jp.transaction_constants(self._read(path))
            if consts:
                result = {name[len("TRANSACTION_"):]: code
                          for name, code in consts.items()
                          if name.startswith("TRANSACTION_")}
        self._iface_cache[fqname] = result
        return result

    # ---- service registration index ------------------------------------- #

    def _registrations(self) -> dict[str, tuple[str, str]]:
        """Map ServiceManager name -> (file, impl-expression) via the register call."""
        if self._registry is not None:
            return self._registry
        reg: dict[str, tuple[str, str]] = {}
        for path in self._java_files():
            src = self._read(path)
            if "BinderService(" not in src and "addService(" not in src:
                continue
            for m in _REGISTER.finditer(src):
                name = m.group("name")
                if name and name not in reg:
                    reg[name] = (path, (m.group("impl") or "").strip())
        self._registry = reg
        return reg

    # ---- analysis -------------------------------------------------------- #

    def analyze_service(self, name: str) -> Optional[ServiceCOD]:
        """COD for the service registered under `name`, or None if not in this jar."""
        reg = self._registrations()
        hit = reg.get(name)
        if hit is None:
            return None
        path, impl_expr = hit
        src = self._read(path)
        impl = self._pick_impl_class(src, impl_expr)
        if impl is None:
            return ServiceCOD(service=name, interface="", impl_class="",
                              impl_file=_rel(self._src, path),
                              note="registered here but no `extends *.Stub` impl class "
                                   "found in the file (impl may be in another unit)")
        return self._analyze_impl(src, impl, path, service=name)

    def analyze_all(self) -> list[ServiceCOD]:
        """COD for every system_server-hosted AIDL service impl in the jar."""
        results: list[ServiceCOD] = []
        reg = self._registrations()
        # name registrations first (authoritative), then any remaining impls.
        seen_files: set[tuple[str, str]] = set()
        for name, (path, impl_expr) in sorted(reg.items()):
            src = self._read(path)
            impl = self._pick_impl_class(src, impl_expr)
            if impl is None:
                continue
            seen_files.add((path, impl.name))
            results.append(self._analyze_impl(src, impl, path, service=name))
        return results

    # ---- impl resolution ------------------------------------------------- #

    def _pick_impl_class(self, src: str, impl_expr: str) -> Optional[jp.JavaClass]:
        """The `extends *.Stub` class in `src` that implements the registered service.

        Prefer the class whose interface matches the registered field's declared type
        when we can read it; otherwise fall back to the sole/first Stub impl in the
        file.
        """
        stubs = [c for c in jp.find_classes(src) if _STUB_EXTENDS.search(c.extends)]
        if not stubs:
            return None
        if len(stubs) == 1:
            return stubs[0]
        # Several Stub impls in one file (callbacks + the service): try to match the
        # registered impl expression's field type, e.g. `this.mService` declared as
        # `IUiModeManager.Stub mService`.
        field_name = impl_expr.split(".")[-1].rstrip("()") if impl_expr else ""
        if field_name:
            fm = re.search(
                rf"([\w.]+)\.Stub\s+{re.escape(field_name)}\b", src)
            if fm:
                iface = fm.group(1)
                for c in stubs:
                    if c.extends.rsplit(".Stub", 1)[0].endswith(iface.split(".")[-1]):
                        return c
        # Fall back to the largest Stub impl (the service, not a small callback).
        return max(stubs, key=lambda c: len(c.body))

    def _analyze_impl(self, src: str, impl: jp.JavaClass, path: str,
                      service: str = "") -> ServiceCOD:
        interface = impl.extends[:-len(".Stub")] if impl.extends.endswith(".Stub") \
            else impl.extends
        cod = ServiceCOD(service=service, interface=interface, impl_class=impl.name,
                         impl_file=_rel(self._src, path))

        # Check corpus: every method in the FILE (impl + enclosing/outer helpers),
        # so a one-hop callee like `enforceFooPermission()` declared on the outer
        # service class is resolvable.
        file_methods = _file_method_index(src)
        impl_methods = {m.name: m for m in jp.find_methods(impl.body)}

        txns = self.interface_transactions(interface)
        if txns is not None:
            # Authoritative: the transaction set and codes come from framework.jar.
            # We classify exactly the interface's methods; an impl that does not
            # override one (inherited elsewhere) is `not-attempted`, not guessed.
            for method, code in sorted(txns.items(), key=lambda kv: kv[1]):
                m = impl_methods.get(method)
                if m is None:
                    cod.transactions.append(Transaction(
                        method, "not-attempted", via="no-override", code=code,
                        note="interface transaction not overridden in this impl "
                             "(inherited from a superclass not resolved here)"))
                    continue
                t = self._classify(m, file_methods)
                t.code = code
                cod.transactions.append(t)
        else:
            # Fallback (interface not in framework.jar, e.g. an APEX javalib): the
            # transaction set is *approximated* from the impl's public methods, which
            # can include non-transaction helpers. Say so, loudly.
            cod.note = ("transaction set approximated from impl public methods "
                        "(interface not found in framework.jar); may include "
                        "non-transaction methods -- treat the ledger as an upper bound")
            for name, m in sorted(impl_methods.items()):
                if not name or not (name[0].isalpha() and name[0].islower()):
                    continue
                if name in _NON_TRANSACTION or name.startswith(("lambda$", "access$")):
                    continue
                if "synthetic" in m.signature:
                    continue
                cod.transactions.append(self._classify(m, file_methods))
        if not cod.transactions and not cod.note:
            cod.note = "impl class found but no transaction methods parsed"
        return cod

    def _classify(self, m: jp.JavaMethod,
                  file_methods: dict[str, jp.JavaMethod]) -> Transaction:
        """Decide one transaction's status from its body + one-hop callees."""
        ev = jp.find_checks(m.body, m.annotations)
        if ev.annotations:
            return Transaction(m.name, "gated", via="annotation",
                               checks=["@" + a for a in ev.annotations],
                               permissions=ev.permissions,
                               note="declaratively enforced by annotation")
        if ev.checks:
            return Transaction(m.name, "gated", via="direct", checks=ev.checks,
                               permissions=ev.permissions)

        # One-hop: follow in-file callees for a check (covers enforce* helpers).
        callees = jp.callees(m.body)
        helper_hit: Optional[tuple[str, jp.CheckEvidence]] = None
        unresolved: list[str] = []
        for cname in sorted(callees):
            callee = file_methods.get(cname)
            if callee is None:
                # A call to something not defined in this file. If it looks like an
                # enforce/permission helper we cannot see, that is exactly the
                # "clean-looking body calling an unfollowed helper" case -> review.
                if _ENFORCE_HELPER.match(cname) or "ermission" in cname:
                    unresolved.append(cname)
                continue
            cev = jp.find_checks(callee.body, callee.annotations)
            if cev.checks or cev.annotations:
                helper_hit = (cname, cev)
                break
        if helper_hit is not None:
            cname, cev = helper_hit
            # A clearly-named enforce helper wrapping a real check is decided-gated;
            # otherwise the one-hop link is weaker -> needs-review.
            decided = bool(_ENFORCE_HELPER.match(cname))
            return Transaction(
                m.name, "gated" if decided else "needs-review",
                via=f"helper:{cname}",
                checks=cev.checks or ["@" + a for a in cev.annotations],
                permissions=cev.permissions,
                note=f"caller check reached via {cname}()"
                     + ("" if decided else "; one-hop link not confirmed to dominate"))
        if unresolved:
            return Transaction(
                m.name, "needs-review", via="unresolved",
                note="no check in the method body, but it calls unresolved helper(s) "
                     f"({', '.join(unresolved[:3])}) that may enforce one; worst-case "
                     "treated as reachable")
        return Transaction(
            m.name, "ungated", via="direct",
            note="method body enforces no caller check and calls no in-file helper "
                 "that does; directly reachable (actionable)")


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def _file_method_index(src: str) -> dict[str, jp.JavaMethod]:
    """Every method declared anywhere in the file, by name (last one wins).

    Used for one-hop callee resolution: a transaction method on a nested Stub impl
    often delegates to an `enforce*` helper on the enclosing service class.
    """
    out: dict[str, jp.JavaMethod] = {}
    for c in jp.find_classes(src):
        for m in jp.find_methods(c.body):
            out[m.name] = m
    return out
