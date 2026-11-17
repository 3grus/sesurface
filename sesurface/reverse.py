"""Inverse of `reach`: given an on-device PATH, which subjects can touch it?

`reach` answers *subject -> objects*. This module answers the dual, *object ->
subjects*: given an absolute on-device path, which SELinux domains can reach it,
and through which gates. It is the natural question for triaging one juicy path
(a specific driver node, a world-readable file) rather than one domain.

Everything here is composition of primitives that already exist for the forward
direction; nothing new touches setools or re-parses the image:

  1. path -> SELinux type, by the same rules the device uses:
       * on-image file  -> the authoritative `security.selinux` xattr
         (`InodeIndex.get`), which also gives the real owner/mode for DAC;
       * kernel pseudo-fs (/proc, /sys, ...) -> genfscon (`Policy.genfs_labels`);
       * runtime path (/data, /dev, ...) -> device-accurate `file_contexts`
         matching (`ContextDB.label_for_path`).
  2. type:class:perms -> candidate source domains, via the reverse TE query
     `Policy.rules_allowing` + attribute expansion `Policy.expand` (the same pair
     the pivot stage uses).
  3. refine each candidate with the other gates exactly as `reach` does: MLS
     (`gates.mls`), DAC on the concrete path (`gates.dac` helpers), and in-code,
     which is UNKNOWN by construction (a static tool can only flag it).

As with `reach`, candidates blocked by a gate are kept and annotated rather than
dropped, so the output is a complete, auditable picture.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass, field
from typing import Optional

from .engine import ImageModel
from .gates import dac, mls
from .model.inode import InodeMeta
from .model.initrc import DomainServiceMap
from .policy.policy import Policy
from .subject import resolve_subject
from .types import Decision, Gate, GateVerdict, Subject

# Object classes backed by a filesystem node -- the only ones a path can denote.
FILE_CLASSES: tuple[str, ...] = (
    "file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file", "fifo_file",
)

# st_mode type bits -> object class (for inferring the class of a real node).
_MODE_CLASS = [
    (stat.S_ISREG, "file"), (stat.S_ISDIR, "dir"), (stat.S_ISLNK, "lnk_file"),
    (stat.S_ISCHR, "chr_file"), (stat.S_ISBLK, "blk_file"),
    (stat.S_ISSOCK, "sock_file"), (stat.S_ISFIFO, "fifo_file"),
]
# file_contexts type specifier -> object class (for runtime paths with no inode).
_SPEC_CLASS = {
    "--": "file", "-d": "dir", "-l": "lnk_file", "-c": "chr_file",
    "-b": "blk_file", "-s": "sock_file", "-p": "fifo_file",
}

# Where each kernel pseudo-filesystem is mounted on the device, so a genfscon
# entry's in-fs path can be turned into an absolute device path. Approximate but
# covers the filesystems genfscon actually labels; documented as such.
_FS_MOUNT = {
    "proc": "/proc", "sysfs": "/sys", "debugfs": "/sys/kernel/debug",
    "tracefs": "/sys/kernel/tracing", "selinuxfs": "/sys/fs/selinux",
    "pstore": "/sys/fs/pstore", "bpf": "/sys/fs/bpf", "functionfs": "/dev/usb-ffs",
}

# A broad "can touch at all" permission set. We pass it to the reverse query only
# as a prefilter and then report each domain's *actual* matched perms, so the exact
# perm semantics of the query do not matter (same approach as pivot.py).
_DEFAULT_PERMS = frozenset({
    "ioctl", "read", "write", "create", "getattr", "setattr", "lock", "append",
    "map", "unlink", "link", "rename", "open", "execute", "search",
    "add_name", "remove_name", "mounton", "relabelfrom", "relabelto",
})


# --------------------------------------------------------------------------- #
# path -> label
# --------------------------------------------------------------------------- #

@dataclass
class PathLabel:
    """The SELinux type a path resolves to, with the evidence and how it was found."""
    path: str
    setype: Optional[str]
    tclass: Optional[str]
    meta: Optional[InodeMeta]     # On-image inode (owner/mode), if the path exists.
    source: str                   # "xattr" | "genfscon" | "file_contexts" | "none".
    evidence: str = ""


def _class_from_mode(mode: Optional[int]) -> Optional[str]:
    if mode is None:
        return None
    for pred, cls in _MODE_CLASS:
        if pred(mode):
            return cls
    return None


def _genfs_lookup(policy: Policy, path: str):
    """The genfscon entry whose (fs-mount + in-fs path) is the longest prefix of `path`."""
    best = None
    best_len = -1
    for gl in policy.genfs_labels():
        mount = _FS_MOUNT.get(gl.fs)
        if mount is None:
            continue
        sub = "" if gl.path == "/" else gl.path
        full = mount.rstrip("/") + sub
        if path == full or path.startswith(full.rstrip("/") + "/"):
            if len(full) > best_len:
                best, best_len = gl, len(full)
    return best


def resolve_path_label(model: ImageModel, policy: Policy, path: str,
                       tclass: Optional[str] = None) -> PathLabel:
    """Resolve an absolute on-device `path` to its SELinux type, device-accurately."""
    meta = model.inodes.get(path)

    # 1. Authoritative xattr for a file that exists in the image.
    if meta is not None and meta.setype:
        cls = tclass or _class_from_mode(meta.mode) or "file"
        return PathLabel(path, meta.setype, cls, meta, "xattr",
                         f"security.selinux xattr on {path}: {meta.setype} "
                         f"[{dac._fmt_meta(meta)}]")

    # 2. genfscon for kernel pseudo-filesystems (/proc, /sys, ...).
    gl = _genfs_lookup(policy, path)
    if gl is not None:
        cls = tclass or _class_from_mode(meta.mode if meta else None) or "file"
        return PathLabel(path, gl.setype, cls, meta, "genfscon",
                         f"genfscon {gl.fs} {gl.path} -> {gl.setype} "
                         f"(approx: {gl.fs} assumed mounted at {_FS_MOUNT.get(gl.fs)})")

    # 3. file_contexts prediction for a runtime path (/data, /dev, ...).
    mode = meta.mode if meta else None
    res = model.contexts.label_for_path(path, mode)
    if res is not None:
        setype, entry = res
        cls = (tclass or (_SPEC_CLASS.get(entry.spec) if entry.spec else None)
               or _class_from_mode(mode) or "file")
        return PathLabel(path, setype, cls, meta, "file_contexts",
                         f"file_contexts predicts {setype}: {entry.describe()}")

    return PathLabel(path, None, tclass, meta, "none",
                     "no xattr, genfscon or file_contexts entry labels this path")


# --------------------------------------------------------------------------- #
# the inverse engine
# --------------------------------------------------------------------------- #

@dataclass
class Toucher:
    """One domain that the TE policy lets reach the path, with the full gate trace."""
    domain: str
    subject: Subject
    perms: frozenset[str]
    gates: dict[Gate, GateVerdict] = field(default_factory=dict)
    source_attrs: tuple[str, ...] = ()   # The attribute(s) the matching rule(s) targeted.
    sample_rule: str = ""

    @property
    def allowed(self) -> bool:
        return all(v.decision is not Decision.DENY for v in self.gates.values())


@dataclass
class ReverseReport:
    """The result of asking who can touch one path."""
    model: ImageModel
    label: PathLabel
    classes: tuple[str, ...]
    perms_queried: frozenset[str]
    te_only: bool
    touchers: list[Toucher] = field(default_factory=list)
    note: str = ""


def _reverse_dac(subject: Subject, model: ImageModel, label: PathLabel,
                 perms: frozenset[str]) -> GateVerdict:
    """DAC for one subject on the *concrete* path (not by type, as the forward gate)."""
    g = Gate.DAC
    if label.tclass not in FILE_CLASSES:
        return GateVerdict(g, Decision.NA, f"{label.tclass} is not a filesystem object")
    want = "write" if (perms & dac._WRITE_PERMS) else "read"

    # On-image path: the authoritative inode + ancestor search check.
    if model.inodes.get(label.path) is not None:
        ok, why = dac._check_path(subject, model.inodes, label.path, want)
        return GateVerdict(g, Decision.ALLOW if ok else Decision.DENY,
                           f"{want} permitted on {label.path}" if ok else why,
                           detail={"operation": want})

    # /dev node with no inode: ueventd.rc declares the uid/gid/mode at runtime.
    if (label.path.startswith("/dev/") and model.ueventd is not None
            and model.aids is not None):
        perm = model.ueventd.resolve(label.path, model.aids)
        if perm is not None:
            meta = InodeMeta(uid=perm.uid, gid=perm.gid, mode=perm.mode,
                             setype=label.setype, caps=None)
            ok = dac._mode_allows(subject, meta, want)
            return GateVerdict(
                g, Decision.ALLOW if ok else Decision.DENY,
                f"{want} {'permitted' if ok else 'blocked'} on {label.path} "
                f"[{perm.fmt()} {perm.rule.source}] (ueventd.rc)",
                detail={"operation": want})

    return GateVerdict(g, Decision.UNKNOWN,
                       f"{label.path} has no inode in the image; DAC depends on the "
                       f"object created at runtime")


def run_who_can_touch(model: ImageModel, policy: Policy, path: str,
                      classes: Optional[list[str]] = None,
                      perms: Optional[frozenset[str]] = None,
                      te_only: bool = False) -> ReverseReport:
    """Enumerate every domain that can reach `path`, refined by all gates."""
    want_perms = frozenset(perms) if perms else _DEFAULT_PERMS
    # If the caller fixed a single class, use it to disambiguate label resolution.
    hint = classes[0] if (classes and len(classes) == 1) else None
    label = resolve_path_label(model, policy, path, tclass=hint)

    eff_classes = tuple(classes) if classes else (
        (label.tclass,) if label.tclass else FILE_CLASSES)

    report = ReverseReport(model=model, label=label, classes=eff_classes,
                           perms_queried=want_perms, te_only=te_only)
    if not label.setype:
        report.note = ("Path could not be labelled, so no domain can be attributed. "
                       "Give --class for a pure runtime path, or check the path.")
        return report

    # Reverse TE query: collect candidate domains and the perms/attribute each gets.
    cand: dict[str, dict] = {}
    for cls in eff_classes:
        for rule in policy.rules_allowing(label.setype, [cls], want_perms):
            for dom in policy.expand(rule.source):
                c = cand.setdefault(dom, {"perms": set(), "src": set(), "sample": ""})
                c["perms"].update(rule.perms)
                c["src"].add(rule.source)
                if not c["sample"]:
                    c["sample"] = rule.sesearch()

    if not cand:
        report.note = (f"No allow rule lets any domain perform "
                       f"{sorted(want_perms)} on {label.setype}:{eff_classes}.")
        return report

    # MLS inputs, computed once (as in gates/combine.build_findings).
    constrained = frozenset(c.tclass for c in policy.mls_constraints())
    trusted_obj = policy.expand("mlstrustedobject")
    dsmap = DomainServiceMap(model.initrc, policy, model.contexts)
    mls_class = label.tclass or eff_classes[0]

    universal = any("domain" in info["src"] for info in cand.values())

    for dom in sorted(cand):
        info = cand[dom]
        p = frozenset(info["perms"])
        subject = resolve_subject(policy, model.contexts, dom,
                                  dsmap=dsmap, aids=model.aids)
        te_ev = info["sample"]
        if subject.is_permissive:
            te_ev += "  | NOTE: domain is permissive (TE not enforced)"
        gates = {Gate.TE: GateVerdict(Gate.TE, Decision.ALLOW, te_ev)}
        if not te_only:
            gates[Gate.MLS] = mls.evaluate(subject, label.setype, mls_class, p,
                                           constrained, trusted_obj)
            gates[Gate.DAC] = _reverse_dac(subject, model, label, p)
            gates[Gate.INCODE] = GateVerdict(
                Gate.INCODE, Decision.UNKNOWN,
                "in-code check needs the server's bytecode (static cannot decide)")
        report.touchers.append(Toucher(
            domain=dom, subject=subject, perms=p, gates=gates,
            source_attrs=tuple(sorted(info["src"])), sample_rule=info["sample"]))

    # Allowed (not gate-blocked) first, then by domain name.
    report.touchers.sort(key=lambda t: (0 if t.allowed else 1, t.domain))
    if universal:
        report.note = (
            "At least one matching rule is written against the `domain` attribute, "
            "so effectively every SELinux domain can perform one of these operations "
            "on this type at the TE layer; MLS/DAC below are what actually narrow it.")
    return report
