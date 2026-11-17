"""The `crown-jewels` preset: who can reach a SELinux-disable primitive, and can
the attacker get to them?

"Disabling SELinux" reduces to reaching one of a small set of primitives:

  * the selinuxfs toggles -- writing `/sys/fs/selinux/enforce` (setenforce) or
    `/sys/fs/selinux/load` (load a replacement policy);
  * the `security` class permissions that back those syscalls -- `setenforce`,
    `load_policy`, `setbool`;
  * the capabilities that yield ring-0 code execution or MAC bypass --
    `capability sys_module` / `sys_rawio`, `capability2 mac_admin` /
    `mac_override`.

This command enumerates the domains that hold each primitive (the holders), and --
given one or more attacker domains via `--from` -- annotates each holder with how
the attacker reaches it (it *is* the attacker, a bug-free BECOMES, or a bug-needing
ATTACKS), using the same reach closure as the `reach` command. The intersection of
"holds a crown jewel" and "reachable from untrusted_app" is the shortest path to a
SELinux-off state; the empty case is itself the finding (a compliant build keeps
these holders unreachable from apps).

Note (necessary-not-sufficient): writing the selinuxfs toggle *also* needs the
matching `security` permission, so cross-reference the path holders with the
`security:setenforce` / `load_policy` holders -- both are listed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .engine import ImageModel
from .policy.policy import Policy
from .reverse import run_who_can_touch
from .types import Decision, Gate


@dataclass(frozen=True)
class Jewel:
    """One SELinux-disable primitive to enumerate holders of."""
    name: str
    kind: str                 # "path" | "class".
    rationale: str
    path: str = ""            # for kind == "path".
    tclass: str = ""          # for kind == "class".
    perms: tuple[str, ...] = ()


# The curated primitive set. Kept tight and direct -- each entry is a genuine route
# to disabling enforcement, not merely a powerful permission.
CROWN_JEWELS: tuple[Jewel, ...] = (
    Jewel("selinux enforce toggle", "path",
          "write flips global enforcing off (also needs security:setenforce)",
          path="/sys/fs/selinux/enforce"),
    Jewel("selinux policy reload", "path",
          "write loads a replacement policy (also needs security:load_policy)",
          path="/sys/fs/selinux/load"),
    Jewel("security:setenforce", "class",
          "the setenforce() backing permission -> disable enforcing",
          tclass="security", perms=("setenforce",)),
    Jewel("security:load_policy", "class",
          "load a crafted replacement policy",
          tclass="security", perms=("load_policy",)),
    Jewel("security:setbool", "class",
          "flip policy booleans to widen access at runtime",
          tclass="security", perms=("setbool",)),
    Jewel("capability:sys_module", "capability",
          "insert a kernel module -> ring-0 code execution",
          tclass="capability", perms=("sys_module",)),
    Jewel("capability:sys_rawio", "capability",
          "raw I/O / iopl -> direct kernel memory access",
          tclass="capability", perms=("sys_rawio",)),
    Jewel("capability2:mac_admin", "capability2",
          "CAP_MAC_ADMIN: set/relabel SELinux contexts, write policy",
          tclass="capability2", perms=("mac_admin",)),
    Jewel("capability2:mac_override", "capability2",
          "CAP_MAC_OVERRIDE: bypass MAC on access checks",
          tclass="capability2", perms=("mac_override",)),
)


@dataclass
class JewelHolder:
    domain: str
    reach: str = ""           # "" | "self" | "BECOMES" | "ATTACKS".
    gate_note: str = ""       # for path jewels: the DAC/MLS verdict summary.
    evidence: str = ""        # a sesearch line or file_contexts evidence.

    @property
    def reachable(self) -> bool:
        return self.reach != ""


@dataclass
class JewelResult:
    jewel: Jewel
    resolved: str             # "selinuxfs via genfscon" or "security:setenforce".
    holders: list[JewelHolder] = field(default_factory=list)
    note: str = ""


@dataclass
class CrownJewelReport:
    model: ImageModel
    attacker: tuple[str, ...]
    results: list[JewelResult] = field(default_factory=list)


def _reach_label(domain: str, selfset: frozenset[str],
                 becomes: frozenset[str], attacks: frozenset[str]) -> str:
    """How an attacker reaches `domain` (most-direct wins)."""
    if domain in selfset:
        return "self"
    if domain in becomes:
        return "BECOMES"
    if domain in attacks:
        return "ATTACKS"
    return ""


def _gate_summary(toucher) -> str:
    """Short DAC/MLS note for a path-jewel holder (TE already implied)."""
    bits = []
    for g in (Gate.MLS, Gate.DAC):
        v = toucher.gates.get(g)
        if v is not None:
            bits.append(f"{g.value.upper() if g is Gate.DAC else 'MLS'}={v.decision.value}")
    return " ".join(bits)


def _attacker_closure(model: ImageModel, policy: Policy,
                      attacker: tuple[str, ...]):
    """(self, BECOMES, ATTACKS) domain sets reachable from the attacker domains."""
    from .engine import run_reach
    selfset, becomes, attacks = set(attacker), set(), set()
    for dom in attacker:
        if not policy.is_type(dom):
            continue
        rr = run_reach(model, policy, dom)
        becomes |= set(rr.te.reached_domains)
        becomes.add(dom)
        attacks |= {p.to_domain for p in rr.pivots.attacks}
    # A domain reached both ways is labelled by the stronger (BECOMES) edge.
    attacks -= becomes
    return frozenset(selfset), frozenset(becomes), frozenset(attacks)


def run_crown_jewels(model: ImageModel, policy: Policy,
                     attacker: Optional[list[str]] = None) -> CrownJewelReport:
    """Enumerate holders of every crown jewel, annotated by attacker reach."""
    att = tuple(attacker or ())
    report = CrownJewelReport(model=model, attacker=att)

    if att:
        selfset, becomes, attacks = _attacker_closure(model, policy, att)
    else:
        selfset = becomes = attacks = frozenset()

    for jewel in CROWN_JEWELS:
        if jewel.kind == "path":
            res = _path_holders(model, policy, jewel)
        else:
            res = _perm_holders(policy, jewel)
        for h in res.holders:
            h.reach = _reach_label(h.domain, selfset, becomes, attacks)
        # Reachable-from-attacker first, then by domain.
        res.holders.sort(key=lambda h: (0 if h.reachable else 1, h.domain))
        report.results.append(res)
    return report


def _path_holders(model: ImageModel, policy: Policy, jewel: Jewel) -> JewelResult:
    rep = run_who_can_touch(model, policy, jewel.path, perms=frozenset({"write"}))
    lab = rep.label
    resolved = (f"{lab.setype} via {lab.source}" if lab.setype
                else "unresolved (not labelled in this image)")
    res = JewelResult(jewel=jewel, resolved=resolved, note=rep.note)
    # Holders = domains with a write allow that is not DAC/MLS-blocked.
    for t in rep.touchers:
        if t.allowed:
            res.holders.append(JewelHolder(
                domain=t.domain, gate_note=_gate_summary(t),
                evidence=t.sample_rule))
    if not res.holders and lab.setype:
        res.note = (res.note + "  "
                    + "no un-blocked writer (good: the toggle is not app-writable)").strip()
    return res


def _perm_holders(policy: Policy, jewel: Jewel) -> JewelResult:
    doms: dict[str, str] = {}   # domain -> sample sesearch evidence.
    for rule in policy.rules_with_perm(jewel.tclass, jewel.perms):
        ev = rule.sesearch()
        for d in policy.expand(rule.source):
            doms.setdefault(d, ev)
    res = JewelResult(jewel=jewel,
                      resolved=f"{jewel.tclass}:{','.join(jewel.perms)}")
    for d, ev in doms.items():
        res.holders.append(JewelHolder(domain=d, evidence=ev))
    return res
