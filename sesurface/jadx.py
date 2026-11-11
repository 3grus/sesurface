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
    impl_file: str                      # class path within its jar, e.g. com/android/...
    transactions: list[Transaction] = field(default_factory=list)
    note: str = ""
    impl_jar: str = ""                  # on-device jar the impl ships in (the file to open)

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

@dataclass
class _Resolved:
    """A registered service resolved to the code needed to classify it."""
    interface: str                                  # AIDL interface fqname
    impl_class: str
    path: str                                       # file the concrete impl lives in
    impl_methods: dict                              # name -> JavaMethod (impl + bases)
    file_methods: dict                              # name -> JavaMethod (for 1-hop)


_STUB_EXTENDS = re.compile(r"\.Stub$")
_REGISTER = re.compile(
    r"(?:publishBinderService|ServiceManager\.addService|addService)\s*\(\s*"
    r'"(?P<name>[\w./-]+)"\s*,\s*(?P<impl>[^;\n]{0,200})')

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

    def __init__(self, sources_dir, framework_dir: Optional[str] = None,
                 root_origins: Optional[dict] = None):
        # One analyzer can span several decompiled trees: services.jar plus the APEX
        # `javalib` service jars (appsearch, tethering/connectivity, wifi, uwb, ...),
        # whose impls register and enforce exactly like the in-tree ones. `sources_dir`
        # may be a single path (back-compat) or a list of source roots.
        self._srcs: list[str] = ([sources_dir] if isinstance(sources_dir, str)
                                 else list(sources_dir))
        self._src = self._srcs[0] if self._srcs else ""
        # {decompiled source root -> the on-device jar it was decompiled from}, so a
        # resolved impl can name the exact file an analyst opens (services.jar vs a
        # particular APEX javalib jar). Keys are normalised absolute paths.
        self._origins: dict[str, str] = {os.path.abspath(k): v
                                         for k, v in (root_origins or {}).items()}
        # Optional decompiled framework.jar: supplies the authoritative transaction
        # set (and numeric codes) per AIDL interface, which services.jar lacks.
        self._fw = framework_dir
        self._files: Optional[list[str]] = None
        self._registry: Optional[dict[str, tuple[str, str]]] = None  # name->(file, impl)
        self._clocs: Optional[dict[str, list[str]]] = None    # class name -> files
        self._children: dict[str, list[str]] = {}             # parent -> [subclasses]
        self._parsed: dict[str, list] = {}                    # file -> [JavaClass]
        self._iface_cache: dict[str, Optional[dict[str, int]]] = {}

    # ---- tree plumbing --------------------------------------------------- #

    def _java_files(self) -> list[str]:
        if self._files is None:
            out: list[str] = []
            for src in self._srcs:
                for root, _dirs, files in os.walk(src):
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

    def _relpath(self, path: str) -> str:
        """Path relative to whichever source root contains it (for display)."""
        best = path
        for src in self._srcs:
            r = _rel(src, path)
            if not r.startswith("..") and len(r) < len(best):
                best = r
        return best

    def _origin_jar(self, path: str) -> str:
        """The on-device jar a decompiled file came from (via its source root)."""
        ap = os.path.abspath(path)
        for src in sorted(self._srcs, key=len, reverse=True):
            if ap.startswith(os.path.abspath(src) + os.sep):
                return self._origins.get(os.path.abspath(src), "")
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

    def _build_index(self) -> None:
        """One pass over the tree: service registrations + a class-name -> files map.

        The class map is built with a cheap `class <Name>` scan (no brace matching),
        so resolving an impl that lives in a *different* file than its
        `publishBinderService(...)` call only has to fully parse the few files on that
        impl's inheritance chain, not the whole tree.
        """
        if self._registry is not None:
            return
        reg: dict[str, tuple[str, str]] = {}
        clocs: dict[str, list[str]] = {}
        children: dict[str, list[str]] = {}
        cname = re.compile(r"\bclass\s+(\w+)(?:\s*<[^{]*?>)?(?:\s+extends\s+([\w.]+))?")
        for path in self._java_files():
            src = self._read(path)
            for m in cname.finditer(src):
                clocs.setdefault(m.group(1), []).append(path)
                if m.group(2):
                    parent = m.group(2).split(".")[-1]
                    children.setdefault(parent, []).append(m.group(1))
            if "BinderService(" in src or "addService(" in src:
                for m in _REGISTER.finditer(src):
                    name = m.group("name")
                    if name and name not in reg:
                        reg[name] = (path, (m.group("impl") or "").strip())
        self._registry = reg
        self._clocs = clocs
        self._children = children

    def _registrations(self) -> dict[str, tuple[str, str]]:
        self._build_index()
        return self._registry        # type: ignore[return-value]

    def _classes_in(self, path: str) -> list[jp.JavaClass]:
        if path not in self._parsed:
            self._parsed[path] = jp.find_classes(self._read(path))
        return self._parsed[path]

    def _find_class(self, simple_name: str) -> Optional[tuple[str, jp.JavaClass]]:
        """Locate a class by simple name (first definition found), with its file."""
        self._build_index()
        for path in (self._clocs or {}).get(simple_name, []):
            for c in self._classes_in(path):
                if c.name == simple_name:
                    return path, c
        return None

    def _descendant_classes(self, name: str,
                            _depth: int = 3) -> list[tuple[str, jp.JavaClass]]:
        """Concrete subclasses of `name` (transitively, a few levels), file + class.

        The registered object is sometimes typed as an abstract base; its real
        transaction overrides live in the subclass, so we gather those too.
        """
        self._build_index()
        out: list[tuple[str, jp.JavaClass]] = []
        seen: set[str] = set()
        frontier = [name]
        for _ in range(_depth):
            nxt: list[str] = []
            for parent in frontier:
                for child in self._children.get(parent, []):
                    if child in seen:
                        continue
                    seen.add(child)
                    hit = self._find_class(child)
                    if hit is not None:
                        out.append(hit)
                    nxt.append(child)
            frontier = nxt
        return out

    # ---- analysis -------------------------------------------------------- #

    def analyze_service(self, name: str) -> Optional[ServiceCOD]:
        """COD for the service registered under `name`, or None if not in this jar."""
        if name not in self._registrations():
            return None
        res = self._resolve(name)
        if res is None:
            path = self._registrations()[name][0]
            return ServiceCOD(service=name, interface="", impl_class="",
                              impl_file=self._relpath(path), impl_jar=self._origin_jar(path),
                              note="registered here but its `extends *.Stub` impl could "
                                   "not be resolved (impl in an unparsed unit, or a "
                                   "non-literal registration)")
        return self._analyze(res, service=name)

    def analyze_all(self) -> list[ServiceCOD]:
        """COD for every system_server-hosted AIDL service impl in the jar."""
        results: list[ServiceCOD] = []
        for name in sorted(self._registrations()):
            res = self._resolve(name)
            if res is not None:
                results.append(self._analyze(res, service=name))
        return results

    # ---- impl resolution ------------------------------------------------- #

    def _resolve(self, name: str) -> Optional["_Resolved"]:
        """Resolve a registered service to its concrete impl + AIDL interface.

        Handles both the easy case (the `extends *.Stub` impl is a class in the same
        file as the registration) and the common harder case where the registered
        object's type is declared in another file and reaches the AIDL Stub through a
        chain of superclasses (e.g. `AppWidgetServiceImpl`, or
        `DevicePolicyManagerService extends BaseIDevicePolicyManager extends
        IDevicePolicyManager.Stub`).
        """
        reg_path, impl_expr = self._registrations()[name]
        reg_src = self._read(reg_path)

        # 1) Same-file Stub impl (nested or top-level).
        impl = self._pick_impl_class(reg_src, impl_expr)
        if impl is not None:
            return _Resolved(
                interface=impl.extends[:-len(".Stub")],
                impl_class=impl.name, path=reg_path,
                impl_methods={m.name: m for m in jp.find_methods(impl.body)},
                file_methods=_file_method_index(reg_src))

        # 2) Cross-file: resolve the registered object's type, walk to its Stub.
        typename = self._impl_typename(reg_src, impl_expr)
        if typename:
            return self._resolve_typename(typename)
        return None

    @staticmethod
    def _first_arg(raw: str) -> str:
        """The first (impl) argument of a register call, ignoring commas in parens."""
        depth = 0
        out = []
        for ch in raw:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                break
            out.append(ch)
        return "".join(out).strip()

    def _impl_typename(self, src: str, impl_expr: str) -> Optional[str]:
        """The concrete class of the object passed to publishBinderService/addService.

        Handles the forms seen in services.jar: `new FooImpl(...)`, a cast
        `(IBinder) foo`, a variable assigned `v = new Concrete(...)` or a factory
        `v = Concrete.main(...)`, and a plain variable whose declared type is concrete.
        A variable whose only type is the AIDL interface (`IFoo.Stub v`, `IBinder v`)
        is left unresolved rather than guessed.
        """
        if not impl_expr:
            return None
        arg = self._first_arg(impl_expr)
        arg = re.sub(r"^\([\w.]+\)\s*", "", arg).strip()      # strip a cast
        m = re.match(r"new\s+([\w.]+)", arg)
        if m:
            return m.group(1).split(".")[-1]
        m = re.match(r"([\w.]+)\.\w+\s*\(", arg)              # Concrete.main(...) factory
        if m:
            return m.group(1).split(".")[-1]
        var = re.match(r"([A-Za-z_]\w*)", arg.replace("this.", ""))
        var = var.group(1) if var else ""
        if not var or var in ("this", "super"):
            return None
        # Resolve the variable: an assignment to a concrete type (including an
        # `outer.new Inner()` or a `Factory.create(...)`) wins over the declared type,
        # which is often just the AIDL interface.
        am = re.search(rf"\b{re.escape(var)}\s*=\s*[^;]*?\bnew\s+([\w.]+)", src)
        if am:
            return am.group(1).split(".")[-1]
        fm = re.search(rf"\b{re.escape(var)}\s*=\s*([\w.]+)\.\w+\s*\(", src)
        if fm:
            return fm.group(1).split(".")[-1]
        dm = re.search(rf"\b([A-Z]\w*(?:\.\w+)*)\s+{re.escape(var)}\s*[;=,)]", src)
        if dm:
            t = dm.group(1)
            if t.endswith(".Stub") or re.fullmatch(r"I[A-Z]\w*", t.split(".")[-1]):
                return None     # interface-typed field; concrete impl assigned elsewhere
            return t.split(".")[-1]
        return None

    def _resolve_typename(self, typename: str) -> Optional["_Resolved"]:
        """Walk `typename`'s superclass chain to the `*.Stub` that names the AIDL IFace.

        Collects the impl methods across the whole chain (an override may live on the
        concrete class or an intermediate base) and the enclosing files' methods for
        one-hop caller-check helper resolution.
        """
        chain: list[tuple[str, jp.JavaClass]] = []
        seen: set[str] = set()
        cur = typename
        for _ in range(6):
            if cur in seen:
                break
            seen.add(cur)
            hit = self._find_class(cur)
            if hit is None:
                break
            path, cls = hit
            chain.append((path, cls))
            if cls.extends.endswith(".Stub"):
                # The registered object may be a *subclass* of the declared type (e.g.
                # declared BaseIDevicePolicyManager, actually DevicePolicyManagerService).
                # Pull in subclass bodies too so their overrides aren't counted as
                # "not-attempted". Subclass methods win over the base's.
                subs = self._descendant_classes(typename)
                impl_methods: dict[str, jp.JavaMethod] = {}
                files: set[str] = set()
                for p, c in subs + chain:              # subclasses first, then bases
                    files.add(p)
                    for mm in jp.find_methods(c.body):
                        impl_methods.setdefault(mm.name, mm)
                file_methods: dict[str, jp.JavaMethod] = {}
                for p in files:
                    for k, v in _file_method_index(self._read(p)).items():
                        file_methods.setdefault(k, v)
                concrete = subs[0][1].name if subs else chain[0][1].name
                cpath = subs[0][0] if subs else chain[0][0]
                return _Resolved(
                    interface=cls.extends[:-len(".Stub")],
                    impl_class=concrete, path=cpath,
                    impl_methods=impl_methods, file_methods=file_methods)
            cur = cls.extends.split("<")[0].strip().split(".")[-1]
            if not cur:
                break
        return None

    def _pick_impl_class(self, src: str, impl_expr: str) -> Optional[jp.JavaClass]:
        """The `extends *.Stub` class in `src` that implements the registered service.

        Prefer the class whose interface matches the registered field's declared type
        when we can read it; otherwise fall back to the sole/largest Stub impl in the
        file. Returns None when the file defines no `*.Stub` impl at all.
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

    def _analyze(self, res: "_Resolved", service: str = "") -> ServiceCOD:
        interface = res.interface
        cod = ServiceCOD(service=service, interface=interface,
                         impl_class=res.impl_class,
                         impl_file=self._relpath(res.path),
                         impl_jar=self._origin_jar(res.path))
        file_methods = res.file_methods
        impl_methods = res.impl_methods

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
