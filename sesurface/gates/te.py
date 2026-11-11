"""Gate 1: SELinux type enforcement -- the reachability layers.

This computes every object type the subject's domain can touch *according to the
allow rules*, which is the first and widest gate. The other gates (MLS, DAC,
in-code) only ever narrow this set. We produce it in layers so each finding records
how it was reached:

  * direct      -- an `allow` rule sourced at the subject's domain (attribute-
                   expanded). The core of the result.
  * transition  -- the subject can become another domain by exec'ing a binary
                   (a BECOMES pivot); that new domain's direct rules are reachable
                   too. We follow these, recording the via-domain.

A third, noisier information-flow layer exists in the policy adapter but is optional
and off by default here (see `Policy.infoflow_targets` for why it under-counts
binder/property flows); the direct + transition layers plus the pivot stage's
reverse query cover reachability without its noise.

`allowxperm` rules (ioctl command whitelists) are folded into the matching object so
a device-node finding can show exactly which driver ioctls the subject may issue --
the precise kernel attack surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..policy.policy import AllowRule, Policy
from ..types import Pivot, PivotKind


@dataclass
class TEObject:
    """One reachable (type, class) with its permissions and provenance."""
    setype: str
    tclass: str
    perms: set[str] = field(default_factory=set)
    xperms: list[str] = field(default_factory=list)   # ioctl command ranges, if any.
    layers: set[str] = field(default_factory=set)      # {"direct","transition"}.
    via_domains: set[str] = field(default_factory=set)  # domains routed through.
    sample_rule: str = ""                               # a sesearch line (evidence).

    def key(self) -> tuple[str, str]:
        return (self.tclass, self.setype)


@dataclass
class TEReach:
    """The full TE reachability result for one subject."""
    source_domain: str
    reached_domains: set[str] = field(default_factory=set)   # via process transitions.
    objects: dict[tuple[str, str], TEObject] = field(default_factory=dict)
    pivots: list[Pivot] = field(default_factory=list)        # BECOMES edges (transitions).
    permissive_note: str = ""

    def _fold(self, rule: AllowRule, layer: str, via: str = "") -> None:
        """Merge one allow/allowxperm rule into the object table."""
        key = (rule.tclass, rule.target)
        obj = self.objects.get(key)
        if obj is None:
            obj = TEObject(setype=rule.target, tclass=rule.tclass)
            self.objects[key] = obj
        obj.layers.add(layer)
        if via:
            obj.via_domains.add(via)
        if rule.xperm:
            if rule.xperm not in obj.xperms:   # dedup identical ioctl ranges.
                obj.xperms.append(rule.xperm)
        else:
            obj.perms.update(rule.perms)
            if not obj.sample_rule:
                obj.sample_rule = rule.sesearch()


def compute_te_reach(policy: Policy, source_domain: str,
                     follow_transitions: bool = True,
                     max_transition_depth: int = 3) -> TEReach:
    """Compute TE reachability for `source_domain`.

    `max_transition_depth` bounds how many exec-transition hops we follow (each hop
    is a BECOMES pivot into a new domain). The default of 3 captures the realistic
    chains (app -> runas -> shell-ish, HAL -> helper) without exploding.
    """
    reach = TEReach(source_domain=source_domain)

    # L0: direct rules sourced at the subject's own domain.
    for rule in policy.allow_rules_from(source_domain):
        reach._fold(rule, "direct")

    if policy.permissive_domains() and source_domain in policy.permissive_domains():
        reach.permissive_note = (
            "source domain is PERMISSIVE: SELinux does not actually enforce these "
            "rules, so the real TE-reachable set is unbounded (any denial is logged, "
            "not blocked). The objects below are the explicitly-allowed ones.")

    # L1: process-transition closure. Each transition is a BECOMES pivot; the new
    # domain's direct rules become reachable, tagged with the via-domain.
    if follow_transitions:
        seen = {source_domain}
        frontier = [(source_domain, 0)]
        while frontier:
            dom, depth = frontier.pop()
            if depth >= max_transition_depth:
                continue
            for edge in policy.transitions_from(dom):
                target = edge.target
                entry = ", ".join(e[0] for e in edge.entrypoints) or "?"
                # Record the pivot (only once per new domain, from the first path).
                if target not in reach.reached_domains:
                    reach.pivots.append(Pivot(
                        kind=PivotKind.BECOMES, to_domain=target,
                        via=f"exec {entry}",
                        rationale=f"{dom} can domain-transition into {target} by "
                                  f"executing {entry}"))
                reach.reached_domains.add(target)
                if target not in seen:
                    seen.add(target)
                    frontier.append((target, depth + 1))
                    # Fold the reached domain's direct rules into the surface.
                    for rule in policy.allow_rules_from(target):
                        reach._fold(rule, "transition", via=target)
    return reach
