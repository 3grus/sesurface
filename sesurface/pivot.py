"""Stage F: pivots -- from reachable objects to new subjects.

Reachability answers "what can the subject touch". Blast radius asks the next
question: "what does touching it GIVE the subject?" We split pivot edges into two
kinds, because they mean very different things (guide ch. 20):

  * BECOMES (S => D): the subject can run code as domain D with no further bug --
    an exec transition, or writing a file D loads/executes as code.
  * ATTACKS (S ~> D): the subject can feed input into D's code, so a bug in D would
    escalate -- a binder call (worst when D has no in-code check, i.e. a HAL), a
    file D parses, an ioctl into a kernel driver.

The engine of this stage is the **reverse "consumers" query**: for each type the
subject can write, ask which domains read, execute or map that type. A domain that
executes/maps it is a BECOMES candidate (it may load the subject's bytes as code); a
domain that only reads it is an ATTACKS candidate (it parses the subject's bytes).

Each edge carries a rank (0 = most severe) and a **lockdown** hint: the single rule
whose removal breaks the edge, which turns a reachability dump into a hardening list.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .policy.policy import Policy
from .types import Decision, Finding, Gate, Pivot, PivotKind, Subject

# Rank bands (lower = more severe), following the guide's ranking order.
_RANK_BECOMES = 5
_RANK_ATTACK_KERNEL = 15
_RANK_ATTACK_HAL = 25
_RANK_ATTACK_FILE = 35
_RANK_ATTACK_SERVICE = 45

_WRITE_PERMS = {"write", "append", "create", "unlink", "setattr", "truncate", "add_name"}
# Types whose wide readability is expected shared content (external/media storage,
# the app's own data). A privileged domain reading these is mostly intended, so we
# rank those ATTACKS edges below reads of more unusual subject-writable types.
_EXPECTED_SHARED = {
    "sdcard_type", "media_rw_data_file", "fuse", "app_fuse_file", "ringtone_file",
    "wallpaper_file", "sdcardfs",
}
# Loading attacker-controlled *code* from a file means executing it. Plain `map`
# (mmap) is excluded on purpose: nearly every domain mmaps shared-memory device
# nodes (ashmem, dmabuf), which is not code loading and would swamp the result.
_CODELOAD_PERMS = {"execute", "execmod"}
# Only real on-disk file objects can be "written then loaded/parsed as a file". A
# device node, socket or fifo is not a file whose bytes a reader interprets, so
# those are not pivot *sources* for the consumers query.
_FILE_SOURCE_CLASSES = {"file", "dir", "lnk_file"}


@dataclass
class PivotReport:
    becomes: list[Pivot] = field(default_factory=list)
    attacks: list[Pivot] = field(default_factory=list)

    def all_ranked(self) -> list[Pivot]:
        return sorted(self.becomes + self.attacks, key=lambda p: p.rank)


def compute_pivots(policy: Policy, subject: Subject, findings: list[Finding],
                   becomes_transitions: list[Pivot]) -> PivotReport:
    """Compute BECOMES and ATTACKS edges from the subject's findings."""
    rep = PivotReport()
    app_domains = policy.expand("appdomain")
    subject_attrs = _subject_attrs(policy, subject)   # computed once.
    seen: set[tuple[str, str, str]] = set()   # (kind, to, via) dedup.

    def add(p: Pivot, bucket: list[Pivot]) -> None:
        k = (p.kind.value, p.to_domain, p.via)
        if k not in seen:
            seen.add(k)
            bucket.append(p)

    # 1. Exec-transition BECOMES edges (already found by the TE layer). Rank by
    #    whether the target escapes the app sandbox (not an app domain).
    for p in becomes_transitions:
        escalates = p.to_domain not in app_domains
        p.rank = _RANK_BECOMES if escalates else _RANK_BECOMES + 20
        p.lockdown = (f"remove the process transition into {p.to_domain} "
                      f"(its init_daemon_domain / domain_auto_trans rule)")
        add(p, rep.becomes)

    # 2. Binder-call ATTACKS edges: reaching a server domain means you can feed its
    #    code. Worst when the server is a HAL (usually no in-code caller check).
    for f in findings:
        if f.tclass != "binder" or not f.allowed:
            continue
        if not (f.perms & {"call", "transfer"}):
            continue
        target = f.setype
        is_hal = _looks_like_hal(target)
        incode = f.gates.get(Gate.INCODE)
        rank = _RANK_ATTACK_HAL if is_hal else _RANK_ATTACK_SERVICE
        why = ("binder call reaches this server; "
               + ("it looks like a HAL/vendor server, which usually does NOT check "
                  "the caller in code, so reachability is effectively real."
                  if is_hal else
                  "its code may still enforce a permission/uid check (in-code gate)."))
        add(Pivot(kind=PivotKind.ATTACKS, to_domain=target,
                  via=f"binder call to {target}", rationale=why, rank=rank,
                  lockdown=f"remove: allow {subject.domain} {target}:binder call",
                  code=list(f.code_artifacts)), rep.attacks)

    # 3. Writable-file consumers: the reverse query. For each real file type the
    #    subject can write, find who executes it (BECOMES) or reads/parses it
    #    (ATTACKS). We aggregate per target domain (one edge per domain, listing the
    #    types) so the output stays readable instead of one row per (domain, type).
    writable = _writable_file_types(findings)
    own = subject.data_type              # the app's own, ubiquitously-read data type.
    expected = _EXPECTED_SHARED | ({own} if own else set())
    becomes_types: dict[str, set[str]] = {}
    attacks_types: dict[str, set[str]] = {}
    attacks_only_expected: dict[str, bool] = {}   # does a domain only read expected types?
    for setype in writable:
        for rule in policy.rules_allowing(setype, list(_FILE_SOURCE_CLASSES),
                                          ["read", "execute", "execmod"]):
            if not (rule.perms & (_CODELOAD_PERMS | {"read"})):
                continue
            for dom in policy.expand(rule.source):
                if dom == subject.domain or dom in subject_attrs or dom in app_domains:
                    continue   # self or lateral (another app) -> not an escalation.
                if rule.perms & _CODELOAD_PERMS:
                    becomes_types.setdefault(dom, set()).add(setype)
                elif "read" in rule.perms:
                    attacks_types.setdefault(dom, set()).add(setype)
                    prev = attacks_only_expected.get(dom, True)
                    attacks_only_expected[dom] = prev and (setype in expected)

    for dom, types in becomes_types.items():
        tlist = ", ".join(sorted(types)[:4])
        add(Pivot(
            kind=PivotKind.BECOMES, to_domain=dom,
            via=f"write a file of type [{tlist}] that {dom} executes as code",
            rationale=(f"{dom} can execute {len(types)} type(s) the subject can write; "
                       f"if it loads code from a path the subject controls, the subject "
                       f"runs as {dom}. Confirm the load path in {dom}'s binary."),
            rank=_RANK_BECOMES,
            lockdown=f"remove {dom}'s execute on the subject-writable type(s): {tlist}"),
            rep.becomes)
    for dom, types in attacks_types.items():
        tlist = ", ".join(sorted(types)[:4])
        # Reading only expected shared content (app's own data, external storage) is
        # mostly intended surface; rank it below domains that parse more unusual
        # subject-writable types.
        only_expected = attacks_only_expected.get(dom, False)
        rank = _RANK_ATTACK_FILE + 10 if only_expected else _RANK_ATTACK_FILE
        note = " (expected shared/app data -- widely read, mostly intended)" if only_expected else ""
        add(Pivot(
            kind=PivotKind.ATTACKS, to_domain=dom,
            via=f"write a file of type [{tlist}] that {dom} reads/parses",
            rationale=(f"{dom} reads {len(types)} type(s) the subject can write{note}; a "
                       f"parsing bug there would run with {dom}'s privileges."),
            rank=rank,
            lockdown=f"remove the subject's write, or {dom}'s read, on: {tlist}"),
            rep.attacks)

    # 4. Kernel-driver ATTACKS: an ioctl into a device node is an attack on the
    #    kernel. The allowxperm whitelist (if any) is the precise surface.
    for f in findings:
        if f.tclass not in ("chr_file", "blk_file") or not f.allowed:
            continue
        if "ioctl" not in f.perms:
            continue
        xperm = ""
        te = f.gates.get(Gate.TE)
        if te and "xperm:" in te.evidence:
            xperm = te.evidence.split("xperm:", 1)[1].strip()
        add(Pivot(kind=PivotKind.ATTACKS, to_domain="kernel",
                  via=f"ioctl on {f.setype} ({f.tclass})",
                  rationale=("ioctl reaches the kernel driver behind this node; the "
                             "allowxperm set is the exact command surface."
                             + (f" xperms: {xperm}" if xperm else
                                " no allowxperm whitelist -> ALL ioctls permitted.")),
                  rank=_RANK_ATTACK_KERNEL,
                  lockdown=(f"narrow allowxperm on {f.setype}:{f.tclass} ioctl"
                            if xperm else
                            f"add an allowxperm ioctl whitelist for {f.setype}"),
                  code=list(f.code_artifacts)), rep.attacks)

    rep.becomes.sort(key=lambda p: p.rank)
    rep.attacks.sort(key=lambda p: p.rank)
    return rep


def _writable_file_types(findings: list[Finding]) -> list[str]:
    """Distinct real file types the subject can write (TE write, not gate-blocked).

    Restricted to file/dir/lnk_file: device nodes, sockets and fifos are not files
    whose bytes a reader later loads or parses. `*_tmpfs` and anonymous types are
    also excluded -- they are shared memory, not path-addressable files a consumer
    opens and parses.
    """
    out: set[str] = set()
    for f in findings:
        if f.tclass not in _FILE_SOURCE_CLASSES or not f.allowed:
            continue
        if not (f.perms & _WRITE_PERMS):
            continue
        if f.setype.endswith("_tmpfs") or f.setype.endswith("tmpfs"):
            continue
        out.add(f.setype)
    return sorted(out)


def _subject_attrs(policy: Policy, subject: Subject) -> frozenset[str]:
    """Attributes the subject's domain belongs to (to exclude self-reads)."""
    return policy.attributes_of(subject.domain)


def _looks_like_hal(setype: str) -> bool:
    return setype.startswith("hal_") or setype.startswith("vendor_") \
        or setype.endswith("_hal") or setype.endswith("_default")
