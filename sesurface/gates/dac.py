"""Gate 1 (classic): discretionary access control -- owner/group/mode over a path.

DAC is the ordinary Unix check, but with two Android-specific points the Chapter 22
review stressed:

  * It must be evaluated on the WHOLE path, not just the leaf. A file may be
    world-writable (0666) yet unreachable because an ancestor directory is 0700. So
    the subject needs search (`x`) on every parent, then the wanted bit on the leaf.
  * The owner/group/mode must come from the real image inodes (what the build wrote),
    which is why `model/inode.py` reads them from the filesystem rather than from an
    extracted tree. This gate just consumes that index.

We report write and read separately where it matters: replacing a file (create/
unlink in its parent directory) is often a stronger primitive than writing it.

Capability bypass (`CAP_DAC_OVERRIDE`) is only available to a few root domains and
*also* needs the SELinux `capability dac_override` permission; apps never have it,
so for app subjects the mode bits are the whole story.
"""

from __future__ import annotations

from typing import Optional

from ..model.inode import InodeIndex, InodeMeta
from ..model.ueventd import UeventdDb, devnodes_for_type
from ..types import Decision, Gate, GateVerdict, Subject, UidClass

# Object classes that are backed by a filesystem node, so DAC applies. Everything
# else (binder, service_manager, property_service, process, abstract sockets) has no
# path to check, and the gate returns NA.
FILE_CLASSES = {
    "file", "dir", "lnk_file", "chr_file", "blk_file", "sock_file", "fifo_file",
}

_READ_PERMS = {"read", "getattr", "open", "search", "ioctl", "map", "execute"}
_WRITE_PERMS = {"write", "append", "create", "unlink", "setattr", "truncate"}


def evaluate_for_type(subject: Subject, index: InodeIndex, setype: str, tclass: str,
                      perms: frozenset[str], sample_limit: int = 50,
                      ueventd: Optional[UeventdDb] = None,
                      aids=None, contexts=None) -> GateVerdict:
    """DAC verdict for a reachable file-like (type, class).

    We look at the concrete inodes carrying `setype` (from the authoritative xattr
    index) and ask whether the subject can perform the operation the perms imply on
    any of them, path-wise. The verdict summarises: ALLOW if at least one backing
    object is reachable (naming it), DENY if objects exist but none are reachable,
    NA if the class is not filesystem-backed, UNKNOWN if the type labels nothing in
    the image (a runtime path -- DAC can only be decided once the object exists).
    """
    g = Gate.DAC
    if tclass not in FILE_CLASSES:
        return GateVerdict(g, Decision.NA, f"{tclass} is not a filesystem object")

    paths = index.paths_for_type(setype, limit=sample_limit)
    if not paths:
        # No inode in the image. For a device node (/dev), ueventd.rc tells us the
        # uid/gid/mode it will be created with at runtime, so DAC is still decidable.
        if tclass == "chr_file" or tclass == "blk_file":
            dev_v = _evaluate_devnode(subject, setype, tclass, perms,
                                      ueventd, aids, contexts)
            if dev_v is not None:
                return dev_v
        return GateVerdict(
            g, Decision.UNKNOWN,
            f"no file in the image carries type {setype}; it is a runtime path "
            f"(/data, /dev, ...), so DAC depends on the object created at runtime")

    want = "write" if (perms & _WRITE_PERMS) else "read"
    allowed_examples: list[str] = []
    blocked_examples: list[str] = []
    for p in paths:
        ok, why = _check_path(subject, index, p, want)
        if ok:
            allowed_examples.append(p)
        else:
            blocked_examples.append(f"{p} ({why})")
        if len(allowed_examples) >= 3 and len(blocked_examples) >= 1:
            break

    if allowed_examples:
        ex = ", ".join(allowed_examples[:3])
        m = _fmt_meta(index.get(allowed_examples[0]))
        return GateVerdict(g, Decision.ALLOW,
                           f"{want} permitted on {ex} [{m}]",
                           detail={"operation": want})
    ex = blocked_examples[0] if blocked_examples else "(all backing objects blocked)"
    return GateVerdict(g, Decision.DENY,
                       f"{want} blocked on every backing object; e.g. {ex}",
                       detail={"operation": want})


def _evaluate_devnode(subject: Subject, setype: str, tclass: str,
                      perms: frozenset[str], ueventd: Optional[UeventdDb],
                      aids, contexts) -> Optional[GateVerdict]:
    """DAC on a /dev node that has no inode, using ueventd.rc's declared perms.

    We find the /dev path(s) this device type labels (from file_contexts), ask
    ueventd what uid/gid/mode it will give them, and apply the ordinary owner/group/
    other check -- but only on the leaf: ueventd does not create the parent /dev
    directories' restrictive modes (those are devtmpfs defaults, world-searchable), so
    the parents do not gate access the way image directories do. Returns None (so the
    caller falls back to UNKNOWN) when we have no ueventd data or no /dev mapping.
    """
    if ueventd is None or aids is None or contexts is None:
        return None
    dev_paths = devnodes_for_type(contexts, setype)
    if not dev_paths:
        return None

    want = "write" if (perms & _WRITE_PERMS) else "read"
    allowed: list[str] = []
    blocked: list[str] = []
    unmatched: list[str] = []
    for dp in dev_paths:
        perm = ueventd.resolve(dp, aids)
        if perm is None:
            unmatched.append(dp)
            continue
        # Build a synthetic InodeMeta from ueventd's declared owner/mode and reuse the
        # same bit check as for real inodes, so the logic stays in one place.
        meta = InodeMeta(uid=perm.uid, gid=perm.gid, mode=perm.mode,
                         setype=setype, caps=None)
        if _mode_allows(subject, meta, want):
            allowed.append(f"{dp} [{perm.fmt()} {perm.rule.source}]")
        else:
            blocked.append(f"{dp} [{perm.fmt()} {perm.rule.source}]")

    if not allowed and not blocked:
        return None   # Nothing matched a ueventd rule; let the caller say UNKNOWN.
    if allowed:
        return GateVerdict(Gate.DAC, Decision.ALLOW,
                           f"{want} permitted on device node {allowed[0]} "
                           f"(perms from ueventd.rc)", detail={"operation": want})
    return GateVerdict(Gate.DAC, Decision.DENY,
                       f"{want} blocked by ueventd mode on every device node; "
                       f"e.g. {blocked[0]}", detail={"operation": want})


def _check_path(subject: Subject, index: InodeIndex, device_path: str,
                want: str) -> tuple[bool, str]:
    """Can the subject do `want` on `device_path`, path components included?

    Returns (allowed, reason). The reason names the component that blocked it, which
    is what makes the verdict auditable.
    """
    # 1. Search on every ancestor directory.
    for ancestor in _ancestors(device_path):
        meta = index.get(ancestor)
        if meta is None:
            continue                        # Ancestor not indexed (e.g. a mountpoint); skip.
        if not _mode_allows(subject, meta, "search"):
            return False, f"no search on ancestor {ancestor} ({_fmt_meta(meta)})"
    # 2. The wanted bit on the leaf.
    leaf = index.get(device_path)
    if leaf is None:
        return False, "leaf not indexed"
    if not _mode_allows(subject, leaf, want):
        return False, f"{want} denied by mode ({_fmt_meta(leaf)})"
    return True, "ok"


def _ancestors(device_path: str) -> list[str]:
    """Every ancestor directory of a path, from the root down (excluding the leaf)."""
    parts = [p for p in device_path.split("/") if p]
    out = []
    for i in range(len(parts) - 1):
        out.append("/" + "/".join(parts[: i + 1]))
    return out


def _mode_allows(subject: Subject, meta: InodeMeta, want: str) -> bool:
    """Classic owner/group/other check for one node.

    `want` is "read", "write", "execute", or "search" (search == execute on a dir).
    For an app subject we never match owner (its uid is a runtime appId, never the
    root/system owner of image files) and we only match a group we positively know
    the subject holds; otherwise we fall to the "other" bits. This is conservative:
    group membership an app could obtain via a permission would only *widen* access,
    and is noted rather than assumed (see module docstring / guide ch. 8).
    """
    if meta.perm is None:
        return False
    perm = meta.perm
    # Root with dac_override bypasses the bits -- but only a few native domains have
    # it, and it also needs the SELinux capability. Apps never do.
    # (We do not grant it here; native-daemon cap handling is a later enrichment.)

    bit = {"read": 0o4, "write": 0o2, "execute": 0o1, "search": 0o1}[want]

    # Owner bits (only if we positively know the subject owns it).
    if subject.uid is not None and meta.uid == subject.uid:
        return bool((perm >> 6) & bit)
    # Group bits (only if we positively know the subject is in the owning group).
    if meta.gid is not None and meta.gid in subject.gids:
        return bool((perm >> 3) & bit)
    # Otherwise: the "other" bits.
    return bool(perm & bit)


def _fmt_meta(meta: Optional[InodeMeta]) -> str:
    if meta is None or meta.perm is None:
        return "unknown"
    return f"{oct(meta.perm)[2:]:>04} {meta.uid}:{meta.gid}"
