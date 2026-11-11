"""Shared data types for sesurface.

This module is the common vocabulary every stage of the pipeline speaks. Nothing
here does any work; it only defines the shapes of the facts we pass around. Keeping
these in one place means a reader can learn the whole data model by reading this one
file, and the stages stay decoupled (the gate engine never imports the setools
adapter, it only produces and consumes these plain dataclasses).

The guiding model (from the "Blast Radius Field Guide"):

    can SUBJECT do OPERATION on OBJECT?  -> yes only if EVERY gate says yes.

So the two central nouns are the `Subject` (who the attacker is after compromise)
and the `Finding` (one object the subject can reach, plus *why* each gate allowed
it). Everything else supports those two.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# --------------------------------------------------------------------------- #
# Gates
# --------------------------------------------------------------------------- #
# Android stacks four independent access checks between a subject and an object.
# An access succeeds only if ALL of them allow it. We model each one's result as
# a `GateVerdict` so that every finding carries a full, auditable row of "which
# gate said what, and on the basis of which concrete artifact".

class Gate(str, Enum):
    """The four gates, in the order the guide presents them."""
    TE = "selinux-te"        # Type Enforcement: the `allow` rule (+ ioctl xperms).
    MLS = "mls"              # Category constraints: app-to-app isolation.
    DAC = "dac"              # Classic Unix owner/group/mode + capabilities.
    INCODE = "in-code"       # The check inside the server's own code.


class Decision(str, Enum):
    """What a gate concluded for one (subject, object, operation) triple.

    ALLOW / DENY are self-explanatory. The two soft values matter because this is
    a *static* tool analysing a firmware image, not a running device:

    - NA ("not applicable"): the gate does not apply to this object class. For
      example, DAC is meaningless for an abstract-namespace socket (it has no
      filesystem entry), and MLS is irrelevant to most system objects at s0.
    - UNKNOWN: the gate *does* apply but we cannot decide it from the image alone.
      The in-code gate is the usual case (it depends on bytecode we have not yet
      decompiled). A finding with an UNKNOWN gate is reported, never silently
      dropped, and is flagged so a human (or the later jadx pass) can resolve it.
    """
    ALLOW = "allow"
    DENY = "deny"
    NA = "n/a"
    UNKNOWN = "unknown"


@dataclass
class GateVerdict:
    """One gate's result for one object, with the evidence behind it.

    `evidence` is the whole point of the tool: a short, human-checkable string that
    names the exact artifact the decision rested on -- a `sesearch` line, a
    `file_contexts` entry, an inode's `uid:gid mode`, or a `.rc` line. If we ever
    need to audit accuracy, this is what we check.
    """
    gate: Gate
    decision: Decision
    evidence: str = ""
    # Optional extra detail keyed by a short label, e.g. {"ancestor": "/data/vendor"}
    # for the DAC gate naming the directory component that gated a path.
    detail: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Subject
# --------------------------------------------------------------------------- #

class UidClass(str, Enum):
    """Which kind of uid the subject runs as.

    This drives both DAC (what groups it has) and MLS (how its category set is
    derived). We reason symbolically: we rarely know the *concrete* appId of an
    app (that is assigned at install time and lives in runtime-only
    `packages.xml`), but we always know its *class*, and that is enough to decide
    the gates. See the guide, chapters 5 and 11.
    """
    ROOT = "root"            # uid 0
    SYSTEM = "system"        # uid 1000 (system_server, platform apps)
    APP = "app"              # 10000-19999, a normal installed app
    ISOLATED = "isolated"    # 99000-99999, isolatedProcess services
    NATIVE = "native"        # a native daemon with a fixed AID (radio, media, ...)
    UNKNOWN = "unknown"


class LevelFrom(str, Enum):
    """How an app domain's MLS categories are assigned (from seapp_contexts).

    This decides whether two apps are isolated from each other by MLS:
    - APP / ALL: each app gets categories derived from its own appId, so apps are
      mutually isolated by MLS.
    - USER: every app of the same Android user shares one category set, so MLS does
      NOT separate them -- only DAC does. These are the weaker neighbours.
    - NONE: no categories (s0), typical of native domains.
    """
    APP = "app"
    USER = "user"
    ALL = "all"
    NONE = "none"


@dataclass
class Subject:
    """Who the attacker is after compromising a process.

    We assume arbitrary native code execution inside the process (a real
    memory-corruption RCE), so the subject holds every credential the process
    holds and the process's own business logic constrains nothing. Only the kernel
    and peer processes do. See the guide, chapter 1 ("What 'compromised' means").
    """
    domain: str                         # SELinux domain/type, e.g. "untrusted_app".
    uid_class: UidClass = UidClass.UNKNOWN
    uid: Optional[int] = None           # Concrete uid when known (native daemons).
    gids: tuple[int, ...] = ()           # Supplementary gids (permission groups, etc.).
    caps: frozenset[str] = frozenset()   # Linux capabilities retained, e.g. "net_admin".
    level_from: LevelFrom = LevelFrom.NONE
    data_type: Optional[str] = None      # The SELinux type of this subject's OWN data
                                         # dir (seapp `type=`), e.g. app_data_file.
                                         # Used by the MLS gate to tell own data from
                                         # another app's same-typed data.
    is_mls_trusted: bool = False         # Carries the `mlstrustedsubject` attribute.
    is_permissive: bool = False          # Domain is permissive -> the TE gate is open.
    # Free-text trace of how this subject was resolved (which seapp line won, which
    # .rc service block, etc.) so the report can explain its own starting point.
    provenance: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Objects, backing, and findings
# --------------------------------------------------------------------------- #

class BackingTier(str, Enum):
    """How well an object the policy *allows* is backed by something real.

    The guide insists every finding says which tier it is in, because a bare list
    of SELinux types over-reports wildly (a rule can allow access to a type that
    labels nothing on this device).
    """
    CONFIRMED = "confirmed"      # A concrete artifact exists in the image (an inode, a
                                 # service_contexts line, a property_contexts entry).
    PREDICTED = "predicted"      # No artifact in the image, but config the tool can read
                                 # creates it at runtime (an .rc mkdir, a ueventd node).
    POLICY_ONLY = "policy-only"  # The rule exists but nothing backs it -- a latent risk,
                                 # worth flagging but not a present object.


@dataclass
class Backing:
    """The concrete object(s) a reachable (type, class) resolves to."""
    setype: str                 # SELinux type of the object, e.g. "gpu_device".
    tclass: str                 # Object class, e.g. "chr_file".
    tier: BackingTier
    kind: str                   # "file" | "device" | "service" | "property" | "socket" | ...
    artifacts: list[str] = field(default_factory=list)  # On-device paths / service names.
    note: str = ""


class PivotKind(str, Enum):
    """What reaching an object *gives* the subject (guide chapter 20).

    - BECOMES: the subject can run code as a new domain with no further bug (an exec
      transition, writing a file a privileged domain loads as code, ctl.start-ing a
      service whose binary the subject controls). These edges are *followed* by the
      reachability closure.
    - ATTACKS: the subject can feed input into another domain's code, so a bug there
      would escalate. These are reported and ranked but not followed by default
      (they need a vulnerability to realise).
    """
    BECOMES = "becomes"
    ATTACKS = "attacks"


@dataclass
class Pivot:
    """An edge from the current subject to a new subject, via some object."""
    kind: PivotKind
    to_domain: str
    via: str                    # Short description of the object/mechanism.
    rationale: str = ""
    rank: int = 50              # 0 = most severe; used only to order the list.
    lockdown: str = ""          # The minimal rule/line to remove to break this edge.
    code: list[str] = field(default_factory=list)   # Candidate handling-code artifacts.


@dataclass
class Finding:
    """One object the subject can reach, with the full gate trace and backing.

    This is the atomic unit of the report and the JSON cache. A finding is only
    emitted for an object the TE gate allows; the other gates then refine it. We
    keep even DENY/UNKNOWN non-TE verdicts attached rather than dropping the
    finding, so the output is a complete, auditable picture -- "the policy allows
    this, but DAC blocks it because ..." is itself a useful, traceable statement.
    """
    setype: str
    tclass: str
    perms: frozenset[str]
    # One verdict per applicable gate, keyed by Gate for easy lookup.
    gates: dict[Gate, GateVerdict] = field(default_factory=dict)
    backing: Optional[Backing] = None
    pivots: list[Pivot] = field(default_factory=list)
    # Which reachability layer surfaced this: "direct" | "transition" | "infoflow".
    layers: frozenset[str] = frozenset()
    # Domains the access was routed through (for transition/infoflow layers).
    via_domains: tuple[str, ...] = ()
    # ioctl command whitelist (allowxperm ranges) the subject may issue on this
    # object, if any. Folded into the TE evidence string too, but kept structured
    # here so the kernel-ioctl attribution pass need not re-parse that string.
    xperms: list[str] = field(default_factory=list)
    # The locator's guess at which code artifact handles this object (filled by
    # stage G; the bridge to the deferred ghidra/jadx attribution pass).
    # `code_artifacts` is the flattened "tool: artifact" form kept for back-compat;
    # `code_refs` preserves each ref's structured (tool, artifact, why) -- the `why`
    # is the per-target instruction the attribution searcher wants.
    code_artifacts: list[str] = field(default_factory=list)
    code_refs: list = field(default_factory=list)   # list[CodeRef] (locate.py).

    @property
    def allowed(self) -> bool:
        """True only if no applicable gate returned DENY.

        UNKNOWN does not count as a denial -- we cannot prove the access is blocked,
        so for a worst-case blast-radius view we treat it as "not ruled out" and
        surface it with its flag. NA gates are ignored.
        """
        return all(
            v.decision is not Decision.DENY
            for v in self.gates.values()
        )
