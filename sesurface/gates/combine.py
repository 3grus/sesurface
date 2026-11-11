"""Combine the four gates into findings.

For each object the TE gate found reachable, run the other three gates, attach the
backing object, and assemble a `Finding`. We keep every gate's verdict -- including
DENY and UNKNOWN ones -- rather than dropping blocked objects, because "the policy
allows this but DAC blocks it" is itself an auditable, useful statement. The
`Finding.allowed` property then reflects whether any applicable gate said DENY.
"""

from __future__ import annotations

from typing import Optional

from ..backing import BackingResolver
from ..model.aids import AidDb
from ..model.contexts import ContextDB
from ..model.inode import InodeIndex
from ..model.ueventd import UeventdDb
from ..policy.policy import Policy
from ..types import Decision, Finding, Gate, GateVerdict, Subject
from . import dac, incode, mls
from .te import TEReach


def build_findings(policy: Policy, subject: Subject, index: InodeIndex,
                   backing: BackingResolver, te_reach: TEReach,
                   ueventd: Optional[UeventdDb] = None,
                   aids: Optional[AidDb] = None) -> list[Finding]:
    """Produce one Finding per reachable object, with all four gate verdicts.

    `ueventd`/`aids` (optional) let the DAC gate decide device-node (`/dev`) findings
    that have no inode in the image, using the perms ueventd will set at runtime.
    """
    # The DAC gate reaches context through the backing resolver's contexts; pull the
    # same ContextDB so device types can be mapped to their /dev file_contexts paths.
    contexts: Optional[ContextDB] = getattr(backing, "_contexts", None)
    findings: list[Finding] = []
    # Compute the MLS inputs once (they are the same for every finding): which
    # classes have an mlsconstrain, and which types are mlstrustedobject.
    constrained_classes = frozenset(c.tclass for c in policy.mls_constraints())
    trusted_objects = policy.expand("mlstrustedobject")
    for (tclass, setype), obj in te_reach.objects.items():
        perms = frozenset(obj.perms)

        # Gate 1 (TE): by construction this object came from an allow rule.
        te_evidence = obj.sample_rule or f"allow {subject.domain} {setype}:{tclass} ..."
        if obj.xperms:
            te_evidence += "  | xperm: " + "; ".join(obj.xperms)
        te_dec = Decision.ALLOW
        if subject.is_permissive:
            te_evidence += "  | NOTE: domain is permissive (TE not enforced)"
        te_v = GateVerdict(Gate.TE, te_dec, te_evidence)

        # Gates 2-4.
        mls_v = mls.evaluate(subject, setype, tclass, perms,
                             constrained_classes, trusted_objects)
        dac_v = dac.evaluate_for_type(subject, index, setype, tclass, perms,
                                      ueventd=ueventd, aids=aids, contexts=contexts)
        incode_v = incode.evaluate(setype, tclass)

        back = backing.resolve(setype, tclass)

        findings.append(Finding(
            setype=setype, tclass=tclass, perms=perms,
            gates={Gate.TE: te_v, Gate.MLS: mls_v, Gate.DAC: dac_v, Gate.INCODE: incode_v},
            backing=back,
            layers=frozenset(obj.layers),
            via_domains=tuple(sorted(obj.via_domains)),
            xperms=list(obj.xperms),
        ))

    # Rank: confirmed-and-allowed first, then by class and type, so the most
    # actionable findings are at the top of the report.
    findings.sort(key=_rank)
    return findings


def _rank(f: Finding):
    """Sort key: allowed before blocked, confirmed before predicted, then class/type."""
    from ..types import BackingTier
    tier_order = {BackingTier.CONFIRMED: 0, BackingTier.PREDICTED: 1,
                  BackingTier.POLICY_ONLY: 2}
    tier = tier_order.get(f.backing.tier, 3) if f.backing else 3
    return (0 if f.allowed else 1, tier, f.tclass, f.setype)
