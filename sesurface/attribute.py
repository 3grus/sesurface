"""Stage H: code-attribution -- resolve the in-code (COD) gate per object class.

This is the pass the four-gate model deferred. For each reachable object, it points
at the *exact handler code* and, where the question applies, decides the in-code gate
the static tool left as `?`: does the handler re-check the caller (UID / permission /
AppOps / peer-cred) before acting?

The strategy is **driven by the object's SELinux class** -- a different class means a
different tool and a different thing to look for (see the dispatch table in the
handoff doc, Part 2 D):

  * `binder` / `unix_stream_socket` / `unix_dgram_socket` (COD `?`)
        The peer is a server *process*. Resolve its binary, follow its `NEEDED`
        libraries to the one that actually hosts the `Bn<Iface>::onTransact` handler,
        and scan that library's dynamic symbols for caller-check primitives
        (`IPCThreadState::getCallingUid`, `checkCallingPermission`, `AppOpsManager`,
        the `*Allowed()` gate helpers, `SO_PEERSEC`/`getpeercon` for sockets). If such
        checks are present the call is **gated** in code (surface narrows, pending a
        per-transaction confirm); if none are, it is **open** (surface confirmed).

  * `hwservice_manager` (HIDL) / passthrough `.so`
        Scan the implementing `.so`. HIDL has no default per-call UID check, so these
        are usually **open**; a passthrough impl runs *in the caller's address space*,
        so a bug there is same-process RCE in the caller, not a cross-domain hop.

  * `chr_file` / `blk_file` device `ioctl`
        Not a "caller check in code" question -- the kernel decides. Decode the
        `allowxperm` command set (the structured `xperms` field) into named driver
        commands (e.g. the `BINDER_*` ioctls) and name the driver entry point. This is
        the precise kernel attack surface (pivot rank 15).

The ELF scan is deterministic and fast (it reads the dynamic symbol table with
`readelf`; it never executes the binary). An optional Ghidra headless pass
(`--ghidra`) deepens a result from "a caller check exists in the handler library" to
"this function calls it", raising confidence. Both are honest about their limits.

**Untrusted-data hygiene:** extracted firmware binaries are untrusted. We decompile
them in an isolated scratch dir, pass paths as args, and never execute them.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .engine import ImageModel
from .locate import CodeLocator, CodeRef, _tool_for_path
from .model.extract import ImageFiles
from .types import Decision, Finding, Gate, GateVerdict


# --------------------------------------------------------------------------- #
# What a caller check looks like in a native server's symbols
# --------------------------------------------------------------------------- #
# Each needle is a substring of a (mangled) symbol an imported/handler function
# would reference to check *who is calling* before acting. Presence in the handler
# library is evidence the server gates the call in code.
CALLER_CHECK_NEEDLES: tuple[str, ...] = (
    "getCallingUid", "getCallingPid",          # IPCThreadState: caller identity
    "checkCallingPermission", "checkPermission",
    "enforceCallingPermission", "enforcePermission",
    "PermissionController", "PermissionChecker",
    "AppOpsManager", "noteOp", "checkOp", "startOp",   # AppOps enforcement
    "AttributionSource",                        # modern permission plumbing
    "Allowed",                                  # recordingAllowed(), settingsAllowed() ...
    "SO_PEERSEC", "getpeercon", "SO_PEERCRED",  # socket peer-credential checks
)

# Standard runtime libraries that never host a service's own transaction handler --
# skipping them keeps a binder finding's lib sweep small and on-point.
_STDLIBS = frozenset({
    "libc.so", "libc++.so", "libm.so", "libdl.so", "liblog.so", "libutils.so",
    "libcutils.so", "libbinder.so", "libhidlbase.so", "libbase.so", "libvndksupport.so",
    "libbacktrace.so", "libunwindstack.so", "ld-android.so", "libnetd_client.so",
})


# --------------------------------------------------------------------------- #
# ioctl command decoding (kernel attack surface)
# --------------------------------------------------------------------------- #
# _IOC packs the command as: nr = cmd & 0xff, type = (cmd >> 8) & 0xff. The SELinux
# xperm set only carries the low 16 bits, which is exactly (type<<8 | nr) for the
# common single-byte drivers, so we can name each command from its (type, nr).
_IOCTL_TABLES: dict[str, tuple[str, str, dict[int, str]]] = {
    # type-char : (driver label, kernel handler symbol, {nr: NAME})
    "b": ("binder (drivers/android/binder.c)", "binder_ioctl", {
        1: "BINDER_WRITE_READ", 3: "BINDER_SET_IDLE_TIMEOUT",
        5: "BINDER_SET_MAX_THREADS", 6: "BINDER_SET_IDLE_PRIORITY",
        7: "BINDER_SET_CONTEXT_MGR", 8: "BINDER_THREAD_EXIT", 9: "BINDER_VERSION",
        11: "BINDER_GET_NODE_DEBUG_INFO", 12: "BINDER_GET_NODE_INFO_FOR_REF",
        13: "BINDER_SET_CONTEXT_MGR_EXT", 14: "BINDER_FREEZE",
        15: "BINDER_GET_FROZEN_INFO", 16: "BINDER_ENABLE_ONEWAY_SPAM_DETECTION",
    }),
}
# A couple of commands worth calling out as the dangerous reach regardless of driver.
_HOT_IOCTLS = {"BINDER_WRITE_READ"}


def _expand_xperm(tok: str) -> list[int]:
    """Expand one xperm string ('ioctl 0x6201 0x6205-0x6209') to command numbers."""
    out: list[int] = []
    for part in tok.replace("ioctl", "").split():
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                out.extend(range(int(a, 16), int(b, 16) + 1))
            else:
                out.append(int(part, 16))
        except ValueError:
            continue
    return out


def decode_ioctls(xperms: list[str]) -> list[tuple[int, str, str]]:
    """Decode xperm ranges to (cmd, driver_handler, NAME) triples."""
    out: list[tuple[int, str, str]] = []
    for tok in xperms:
        for cmd in _expand_xperm(tok):
            tchar = chr((cmd >> 8) & 0xFF)
            nr = cmd & 0xFF
            table = _IOCTL_TABLES.get(tchar)
            if table:
                _label, handler, names = table
                out.append((cmd, handler, names.get(nr, f"(cmd 0x{cmd:04x})")))
            else:
                out.append((cmd, f"ioctl type '{tchar}'", f"(cmd 0x{cmd:04x})"))
    return out


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

@dataclass
class Attribution:
    """The code-attribution result for one finding."""
    setype: str
    tclass: str
    # open       = reachable, a binary WAS scanned and has no caller check (confirmed)
    # gated      = handler re-checks the caller (narrows; per-call confirm pending)
    # unresolved = no server binary could be located to scan -- COD undecided; the
    #              gap is in the locator, not evidence of "no check" (never conflate
    #              with open)
    # aggregate  = the target is a multi-member policy attribute, not one handler; as
    #              reachable as its least-protected member (see per-domain findings)
    # kernel     = kernel-decided ioctl surface (COD n/a, characterised not gated)
    # latent     = nothing on this image provides it (nothing to decompile)
    # skipped    = not an attribution target
    attribution: str
    handler: str = ""                       # the handler symbol / entry point
    artifact: str = ""                      # the file the handler lives in
    tool: str = ""                          # ghidra | jadx | kernel | elf
    caller_check: str = "n/a"               # found | none | n/a
    checks: list[str] = field(default_factory=list)   # demangled caller-check symbols
    ioctls: list[str] = field(default_factory=list)   # "0x6201 BINDER_WRITE_READ (hot)"
    method: str = ""                        # elf-dynsym | ghidra | ioctl-decode | jadx
    confidence: str = ""                    # high | medium | low
    notes: str = ""

    def cod_decision(self) -> Optional[Decision]:
        """The Decision to write into the in-code gate, or None to leave it as-is.

        - open   -> ALLOW: a binary was scanned and does not block; truly reachable.
        - gated  -> stays UNKNOWN, but now *explained*: a caller check is present, so
          whether untrusted_app gets through depends on a runtime grant (worst-case
          still not-ruled-out). We do not fabricate a DENY the image cannot prove.
        - unresolved -> stays UNKNOWN: we could not locate a binary to scan, so the
          gate is simply not yet decided. Crucially we must NOT return ALLOW here --
          "we didn't look" is not "no check".
        - kernel / latent / skipped -> leave the existing decision (n/a or policy).
        """
        if self.attribution == "open":
            return Decision.ALLOW
        return None

    def resolution(self) -> str:
        """How settled this result is -- the audit ledger's status for the finding.

        This is deliberately separate from the *verdict* (open/gated/...): it answers
        "can a reviewer trust this and move on, or does it still need human analysis?"
        so nothing is quietly over- or under-stated.

          decided       -- high-confidence, call-site/structurally confirmed; trust it.
          needs-review  -- a verdict exists but rests on an assumption a human must
                           confirm: a symbol-level (not call-site) scan that could miss
                           an indirect check, a runtime-grant-dependent gate, or an
                           aggregate pointing at member domains.
          not-attempted -- the target is identified but the deciding tool has not run
                           (e.g. the jadx framework pass is deferred/absent).
          unresolved    -- no handler could be located at all; the locator is the gap.
          n/a           -- the class carries no in-code gate (skipped).
        """
        a = self.attribution
        if a == "skipped":
            return "n/a"
        if a == "unresolved":
            return "unresolved"
        if a == "aggregate":
            return "needs-review"          # audit the member domains' own findings
        if self.method == "jadx-deferred":
            return "not-attempted"         # services.jar not decompiled yet
        if a in ("kernel", "latent"):
            return "decided"               # deterministic / genuinely absent
        if self.method in ("ghidra", "jadx"):
            return "decided"               # call-site confirmed
        # elf-dynsym and anything else: symbol-level presence/absence -- real signal,
        # but not a confirmed call site, so a reviewer should still eyeball it.
        return "needs-review"


# --------------------------------------------------------------------------- #
# ELF helpers (read-only; never execute the target)
# --------------------------------------------------------------------------- #

def _readelf_dynsyms(path: str) -> list[str]:
    """Dynamic + full symbol names from an ELF, via readelf (mangled)."""
    try:
        out = subprocess.run(["readelf", "-sW", path], capture_output=True,
                             text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    names: list[str] = []
    for line in out.splitlines():
        # columns: Num: Value Size Type Bind Vis Ndx Name
        parts = line.split()
        if len(parts) >= 8 and parts[0].rstrip(":").isdigit():
            nm = parts[7]
            if nm and nm != "Name":
                names.append(nm.split("@")[0])   # drop @VERSION
    return names


def _readelf_needed(path: str) -> list[str]:
    """NEEDED shared-library names from an ELF's dynamic section."""
    try:
        out = subprocess.run(["readelf", "-dW", path], capture_output=True,
                             text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    needed: list[str] = []
    for line in out.splitlines():
        m = re.search(r"\(NEEDED\).*\[([^\]]+)\]", line)
        if m:
            needed.append(m.group(1))
    return needed


def _demangle(names: list[str]) -> list[str]:
    """Best-effort c++filt demangle (falls back to the mangled name)."""
    if not names:
        return []
    if not shutil.which("c++filt"):
        return names
    try:
        out = subprocess.run(["c++filt"], input="\n".join(names),
                             capture_output=True, text=True, timeout=30).stdout
        return [l for l in out.splitlines() if l]
    except (OSError, subprocess.SubprocessError):
        return names


def _match_checks(names: list[str]) -> list[str]:
    """Mangled symbols that look like caller checks."""
    return sorted({n for n in names
                   if any(k in n for k in CALLER_CHECK_NEEDLES)})


def _has_on_transact(names: list[str]) -> bool:
    """True if a library defines a Bn*::onTransact (it hosts a binder handler)."""
    return any("onTransact" in n and ("Bn" in n or "BnInterface" in n) for n in names)


def _daemon_stem(device_path: str) -> str:
    """A matching stem for a daemon path: 'audioserver' -> 'audio'.

    Used to tie a service's handler library to the daemon (libaudioflinger.so for
    audioserver) rather than to an unrelated dependency that also checks callers.
    """
    base = os.path.basename(device_path).split(".")[0]
    for suf in ("server", "service", "serviced", "daemon", "d"):
        if base.endswith(suf) and len(base) > len(suf) + 2:
            base = base[: -len(suf)]
            break
    return base if len(base) >= 3 else ""


# --------------------------------------------------------------------------- #
# The attributor
# --------------------------------------------------------------------------- #

class Attributor:
    """Resolve the COD gate per finding, by object class, against an image model."""

    def __init__(self, model: ImageModel, locator: CodeLocator, files: ImageFiles,
                 scratch: str, use_ghidra: bool = False,
                 ghidra_home: Optional[str] = None):
        self._model = model
        self._loc = locator
        self._files = files
        self._scratch = scratch
        self._use_ghidra = use_ghidra
        self._ghidra_home = ghidra_home or os.path.expanduser("~/ghidra_12.2_PUBLIC")
        os.makedirs(scratch, exist_ok=True)
        # caches keyed by on-device path
        self._extracted: dict[str, Optional[str]] = {}
        self._syms: dict[str, list[str]] = {}

    # ---- image/file plumbing --------------------------------------------- #

    def _extract(self, device_path: str) -> Optional[str]:
        """Pull a device file into the scratch dir once; return the host path."""
        if device_path in self._extracted:
            return self._extracted[device_path]
        safe = device_path.strip("/").replace("/", "__")
        dest = os.path.join(self._scratch, safe)
        ok = self._files.extract_to(device_path, dest)
        self._extracted[device_path] = dest if ok else None
        return dest if ok else None

    def _device_path_for_lib(self, lib: str) -> Optional[str]:
        """Resolve a NEEDED soname to an on-device path via the inode index."""
        suffix = "/" + lib
        # Prefer the canonical lib dirs, in priority order.
        cands = [p for p in self._model.inodes.meta if p.endswith(suffix)]
        if not cands:
            return None
        order = ("/system/lib64/", "/system/lib/", "/vendor/lib64/", "/vendor/lib/",
                 "/apex/")
        cands.sort(key=lambda p: next((i for i, d in enumerate(order) if d in p), 9))
        return cands[0]

    def _syms_for(self, device_path: str) -> list[str]:
        if device_path in self._syms:
            return self._syms[device_path]
        host = self._extract(device_path)
        syms = _readelf_dynsyms(host) if host else []
        self._syms[device_path] = syms
        return syms

    # ---- dispatch -------------------------------------------------------- #

    def attribute(self, f: Finding) -> Attribution:
        """Resolve one finding's COD gate, dispatching on its object class."""
        tclass = f.tclass
        if tclass in ("binder", "unix_stream_socket", "unix_dgram_socket"):
            return self._attr_server(f)
        if tclass in ("hwservice_manager",):
            return self._attr_hwservice(f)
        if tclass in ("chr_file", "blk_file") and f.xperms:
            return self._attr_ioctl(f)
        return Attribution(f.setype, tclass, "skipped",
                           notes="class carries no in-code gate (decided by TE+DAC)")

    # ---- binder / socket servers ----------------------------------------- #

    def _attr_server(self, f: Finding) -> Attribution:
        """COD for a reachable server process: follow it to the handler library."""
        # A target written against a multi-member attribute (binderservicedomain,
        # hal_drm_server, domain) is not one handler -- it is reach to the socket/binder
        # of *any* member. Don't fan out hundreds of scans or fake a single verdict;
        # label it an aggregate (as reachable as its least-protected member) and point
        # at the members' own per-domain findings. (A single-member attribute like
        # hal_omx_server resolves to its one concrete domain and falls through.)
        is_attr, members = self._loc.member_domains(f.setype)
        if is_attr and len(members) > 1:
            return Attribution(
                f.setype, f.tclass, "aggregate", caller_check="n/a",
                method="policy", confidence="n/a",
                notes=f"policy attribute with {len(members)} member domains "
                      f"(e.g. {', '.join(members[:6])}); not a single handler. As "
                      "reachable as its least-protected member -- see those members' "
                      "own per-domain findings for the in-code verdict.")

        # The daemon binary (often a thin launcher) comes from the locator.
        bin_refs = [r for r in f.code_refs if r.tool in ("ghidra", "jadx")]
        if not bin_refs:
            bin_refs = self._loc.locate_finding(f)
        # Framework (system_server / services.jar) is the jadx half -- flag for jadx.
        for r in bin_refs:
            if r.artifact.endswith(".jar"):
                return Attribution(
                    f.setype, f.tclass, "gated", handler="(Stub.onTransact in "
                    f"{os.path.basename(r.artifact)})", artifact=r.artifact, tool="jadx",
                    caller_check="found", method="jadx-deferred", confidence="low",
                    notes="framework service hosted in system_server; decompile "
                          "services.jar and read the Stub/onTransact permission checks "
                          "(enforceCallingPermission / checkPermission / AppOps)")
            if r.artifact.startswith("("):
                return Attribution(f.setype, f.tclass, "latent", artifact=r.artifact,
                                   notes=r.why or "no host binary on this image")

        # Native server: scan the daemon + the NEEDED libs that host a Bn*::onTransact.
        # The daemon is often a thin launcher, so the real handler lives in a linked
        # library. We score candidate libs so the *handler* we name belongs to this
        # service, not to some unrelated dependency that also happens to check callers.
        all_checks: list[str] = []
        daemon_dev = bin_refs[0].artifact if bin_refs else ""
        stem = _daemon_stem(daemon_dev)
        scan_set: list[str] = []
        if daemon_dev:
            scan_set.append(daemon_dev)
            host = self._extract(daemon_dev)
            for lib in (_readelf_needed(host) if host else []):
                if lib in _STDLIBS:
                    continue
                dev = self._device_path_for_lib(lib)
                if dev:
                    scan_set.append(dev)

        # (device_path, score, checks) for every lib that hosts a handler and checks.
        # `scanned` tracks the binaries we actually read symbols from -- so we can tell
        # "scanned and found no check" (open) from "found nothing to scan" (unresolved).
        scored: list[tuple[str, tuple, list[str]]] = []
        scanned: list[str] = []
        for dev in scan_set:
            syms = self._syms_for(dev)
            if not syms:
                continue
            scanned.append(dev)
            checks = _match_checks(syms)
            has_ot = _has_on_transact(syms)
            if checks:
                all_checks.extend(checks)
            if (has_ot and checks) or (dev == daemon_dev and checks):
                soname = os.path.basename(dev)
                score = (stem != "" and stem in soname,   # belongs to this service
                         has_ot,                           # actually hosts a Bn*::onTransact
                         len(checks))                      # richness of the check set
                scored.append((dev, score, checks))

        scored.sort(key=lambda t: t[1], reverse=True)
        checks_dem = sorted(set(_demangle(sorted(set(all_checks)))))
        artifact = scored[0][0] if scored else (scanned[0] if scanned else daemon_dev)
        default_handler = ("(socket accept/recvmsg loop)"
                           if f.tclass != "binder" else "(server onTransact)")
        if checks_dem:
            attr = Attribution(
                f.setype, f.tclass, "gated",
                handler=self._ontransact_name(artifact, stem) or default_handler,
                artifact=artifact, tool="ghidra", caller_check="found",
                checks=checks_dem[:12], method="elf-dynsym", confidence="medium",
                notes="handler library employs caller checks "
                      f"({', '.join(c.split('(')[0].split('::')[-1] for c in checks_dem[:4])}"
                      "...); per-transaction guard not yet confirmed -- a specific "
                      "transaction code may still be ungated")
        elif scanned:
            # We read a real binary and it referenced no caller-check primitive.
            kind = ("peer-credential (SO_PEERCRED/SO_PEERSEC) or UID "
                    if f.tclass != "binder" else "caller UID / permission / AppOps ")
            attr = Attribution(
                f.setype, f.tclass, "open",
                handler=self._ontransact_name(artifact, stem) or default_handler,
                artifact=artifact, tool="ghidra", caller_check="none",
                method="elf-dynsym", confidence="medium",
                notes=f"scanned {len(scanned)} binary/binaries; no {kind}check symbol "
                      "present -- the server does not re-check the caller; surface "
                      "confirmed")
        else:
            # Nothing resolved to a scannable binary. This is NOT evidence of "no
            # check" -- we never looked. Record it honestly so a reviewer knows the
            # locator (not the handler) is what needs the next step, and which kind.
            if daemon_dev:
                # A binary path was named (from policy or the .rc) but it is not in
                # the carved partitions -- almost always an APEX- or ramdisk-resident
                # daemon, neither of which is indexed yet.
                note = (f"COD undecided: server binary {daemon_dev} is named but not "
                        "present in the carved/indexed partitions (APEX and ramdisk "
                        "are not walked yet); index that partition to scan it.")
            else:
                why = (f.code_refs[0].why if f.code_refs else "") or (
                    "no server binary resolved for this type (a dedicated socket type "
                    "with no accept-side server, or a domain the exec->binary map did "
                    "not cover)")
                note = ("COD undecided: " + why + ". Extend the locator to resolve "
                        "this type to its server binary before the gate can be read.")
            attr = Attribution(
                f.setype, f.tclass, "unresolved", artifact=daemon_dev,
                tool="ghidra", caller_check="unknown", method="locator",
                confidence="none", notes=note)
        if self._use_ghidra and attr.attribution in ("gated", "open") and artifact:
            self._deepen_with_ghidra(attr)
        return attr

    def _ontransact_name(self, device_path: str, stem: str = "") -> str:
        """A representative Bn*::onTransact symbol from a library (demangled).

        Prefers a handler whose interface name relates to the service (the `stem`),
        and avoids thunks and the generic AppOps callback handlers.
        """
        syms = self._syms.get(device_path) or self._syms_for(device_path)
        hits = [n for n in syms if "onTransact" in n and "Bn" in n]
        if not hits:
            return ""
        def rank(n: str) -> tuple:
            # lower is better: service-related first, real symbol before thunk,
            # business handler before the AppOps plumbing.
            return (0 if (stem and stem in n.lower()) else 1,
                    "Thn" in n, "AppOps" in n, len(n))
        hits.sort(key=rank)
        return _demangle([hits[0]])[0]

    # ---- hwservice (HIDL) / passthrough ---------------------------------- #

    def _attr_hwservice(self, f: Finding) -> Attribution:
        """COD for a HIDL HAL: scan the impl .so (passthrough or binderized)."""
        so_refs = [r for r in f.code_refs if r.artifact.endswith(".so")]
        if not so_refs:
            return Attribution(f.setype, f.tclass, "latent",
                               notes="no implementing .so resolved (VINTF latent HAL)")
        dev = so_refs[0].artifact
        passthrough = "passthrough" in (so_refs[0].why or "").lower()
        syms = self._syms_for(dev)
        checks = _demangle(_match_checks(syms))
        fetch = next((n for n in syms if n.startswith("HIDL_FETCH_")), "")
        if checks:
            return Attribution(
                f.setype, f.tclass, "gated", handler=fetch or "(HIDL impl)",
                artifact=dev, tool="ghidra", caller_check="found", checks=checks[:12],
                method="elf-dynsym", confidence="medium",
                notes="HAL impl adds a caller check (unusual for HIDL)")
        note = ("HIDL has no default per-call UID check and this impl adds none "
                "-> open.")
        if passthrough:
            note += (" PASSTHROUGH: dlopen'd into the CALLER's address space, so a bug "
                     "here is same-process RCE in the caller, not a cross-domain hop.")
        return Attribution(
            f.setype, f.tclass, "open", handler=fetch or "(HIDL impl entry)",
            artifact=dev, tool="ghidra", caller_check="none", method="elf-dynsym",
            confidence="medium", notes=note)

    # ---- device ioctl (kernel) ------------------------------------------- #

    def _attr_ioctl(self, f: Finding) -> Attribution:
        decoded = decode_ioctls(f.xperms)
        handler = decoded[0][1] if decoded else "(driver ioctl)"
        lines = []
        for cmd, _h, name in decoded:
            hot = " (hot)" if name in _HOT_IOCTLS else ""
            lines.append(f"0x{cmd:04x} {name}{hot}")
        dev_art = next((r.artifact for r in f.code_refs if r.tool == "kernel"),
                       f.setype)
        return Attribution(
            f.setype, f.tclass, "kernel", handler=handler, artifact=dev_art,
            tool="kernel", caller_check="n/a", ioctls=lines, method="ioctl-decode",
            confidence="high",
            notes=f"{len(decoded)} ioctl command(s) reach the driver's {handler} "
                  "dispatch; COD is n/a (kernel-decided), this is the kernel attack "
                  "surface. " + ("BINDER_WRITE_READ drives the whole transaction "
                  "engine. " if any("BINDER_WRITE_READ" in l for l in lines) else ""))

    # ---- optional ghidra deepening --------------------------------------- #

    def _deepen_with_ghidra(self, attr: Attribution) -> None:
        """Confirm call sites with a Ghidra headless pass (raises confidence)."""
        headless = os.path.join(self._ghidra_home, "support", "analyzeHeadless")
        host = self._extract(attr.artifact) if attr.artifact.startswith("/") else None
        script = os.path.join(os.path.dirname(__file__), "ghidra", "CallerCheckScan.java")
        if not (os.path.exists(headless) and host and os.path.exists(script)):
            return
        proj = os.path.join(self._scratch, "ghidra_proj")
        os.makedirs(proj, exist_ok=True)
        try:
            out = subprocess.run(
                [headless, proj, "attr_" + os.path.basename(host), "-import", host,
                 "-scriptPath", os.path.dirname(script), "-postScript",
                 "CallerCheckScan.java", "-deleteProject"],
                capture_output=True, text=True, timeout=900).stdout
        except (OSError, subprocess.SubprocessError):
            return
        # Headless Ghidra wraps a script's println in a logger prefix
        # ("INFO  CallerCheckScan.java> CALLERCHECK caller -> callee"), so match the
        # marker anywhere in the line, not at its start, and skip the TOTAL line.
        sites = []
        for l in out.splitlines():
            if "CALLERCHECK " not in l or "CALLERCHECK_TOTAL" in l:
                continue
            site = l.split("CALLERCHECK ", 1)[1].strip()
            site = re.sub(r"\s*\(GhidraScript\)\s*$", "", site)   # drop log suffix
            sites.append(site)
        if sites:
            attr.method = "ghidra"
            attr.confidence = "high"
            # Prefer call sites hitting a real permission gate (not ctor/dtor noise)
            # for the human-readable sample.
            strong = [s for s in sites if re.search(
                r"-> .*(Allowed|checkOp|noteOp|getCallingUid|[Pp]ermission)", s)
                and "~" not in s.split("->", 1)[0]]
            sample = "; ".join((strong or sites)[:3])
            attr.notes += (f" [ghidra: {len(sites)} in-code call site(s) to a caller "
                           f"check confirmed, e.g. {sample}]")


# --------------------------------------------------------------------------- #
# Write-back + report
# --------------------------------------------------------------------------- #

def writeback(f: Finding, attr: Attribution) -> None:
    """Fold the attribution into the finding's in-code gate (§F: close the loop)."""
    v = f.gates.get(Gate.INCODE)
    if v is None:
        v = GateVerdict(Gate.INCODE, Decision.UNKNOWN)
        f.gates[Gate.INCODE] = v
    new = attr.cod_decision()
    if new is not None:
        v.decision = new
    bits = [f"attribution={attr.attribution}"]
    if attr.handler:
        bits.append(f"handler={attr.handler}")
    if attr.caller_check != "n/a":
        bits.append(f"caller-check={attr.caller_check}")
    if attr.ioctls:
        bits.append("ioctls=[" + "; ".join(attr.ioctls) + "]")
    v.evidence = "  |  ".join(bits)
    v.detail = {
        "attribution": attr.attribution,
        "resolution": attr.resolution(),
        "handler": attr.handler,
        "artifact": attr.artifact,
        "tool": attr.tool,
        "caller_check": attr.caller_check,
        "checks": ", ".join(attr.checks),
        "ioctls": "; ".join(attr.ioctls),
        "method": attr.method,
        "confidence": attr.confidence,
        "notes": attr.notes,
    }


def attribute_findings(model: ImageModel, locator: CodeLocator, files: ImageFiles,
                       findings: list[Finding], scratch: str,
                       use_ghidra: bool = False,
                       only_targets: bool = True) -> list[Attribution]:
    """Attribute findings (COD-? servers, HIDL HALs, device-ioctl), writing back.

    `only_targets=True` restricts to findings whose COD gate is actually open to
    attribution (unknown binder/socket, hwservice, device-ioctl), i.e. skips the
    already-decided file/dir/process surface.
    """
    attr = Attributor(model, locator, files, scratch, use_ghidra=use_ghidra)
    results: list[Attribution] = []
    for f in findings:
        a = attr.attribute(f)
        if only_targets and a.attribution == "skipped":
            continue
        writeback(f, a)
        results.append(a)
    return results
