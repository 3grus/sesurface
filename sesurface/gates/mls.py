"""Gate 3: MLS / MCS categories -- app-to-app isolation.

Plain type enforcement says `untrusted_app` may read `app_data_file`, and *every*
app's private data is `app_data_file`. If we stopped there we would claim a
compromised app can read every app's data, which is wrong: MLS categories (and DAC)
stop it. This gate applies the part of the Android MLS model we can decide
statically, and is careful **not to over-deny** -- for an exhaustive surface tool, a
false DENY hides real surface, which is worse than a noted ALLOW.

What we can decide with confidence (guide ch. 11):

  * A class with no `mlsconstrain` is unaffected -> n/a.
  * A subject at s0 (no categories -- most native daemons) satisfies every
    constraint trivially -> n/a.
  * An `mlstrustedsubject`, or an `mlstrustedobject` target, is exempt -> allow.
  * Against another instance of the subject's OWN data type (another app's
    `app_data_file`): this is the isolation MLS actually provides. With levelFrom
    all/app each app has distinct categories, so another app's data is blocked; with
    levelFrom user, all apps of one user share categories, so MLS does NOT isolate
    them (only DAC does). We state this as detail on the finding.

For every other constrained object we return ALLOW with a note: statically we cannot
pin the object instance's level (many per-domain objects are created at the
subject's own level, and most system objects sit at s0 and are readable), so we do
not manufacture a DENY we cannot justify. The one isolation guarantee MLS gives --
separating a categorised subject from other categorised subjects' data -- is
reported where it applies, above.
"""

from __future__ import annotations

from typing import Optional

from ..types import Decision, Gate, GateVerdict, LevelFrom, Subject


def evaluate(subject: Subject, setype: str, tclass: str, perms: frozenset[str],
             constrained_classes: frozenset[str],
             trusted_objects: frozenset[str]) -> GateVerdict:
    """Decide the MLS gate for one reachable (type, class, perms)."""
    g = Gate.MLS

    if tclass not in constrained_classes:
        return GateVerdict(g, Decision.NA, f"{tclass} has no mlsconstrain")

    # s0 subject: no categories, so dominate and equal both hold trivially.
    if not _has_categories(subject):
        return GateVerdict(g, Decision.NA,
                           "subject runs at s0 (no categories); MLS constraints are "
                           "trivially satisfied")

    if subject.is_mls_trusted:
        return GateVerdict(g, Decision.ALLOW,
                           "subject is mlstrustedsubject: exempt from MLS categories")

    if setype in trusted_objects:
        return GateVerdict(g, Decision.ALLOW,
                           f"{setype} is mlstrustedobject: exempt from MLS categories")

    # The one isolation MLS actually enforces: another app's copy of the subject's
    # own data type.
    if subject.data_type and setype == subject.data_type:
        if subject.level_from in (LevelFrom.ALL, LevelFrom.APP):
            return GateVerdict(
                g, Decision.ALLOW,
                f"own {setype} only; ANOTHER app's {setype} is blocked by MLS "
                f"(levelFrom={subject.level_from.value}: per-app categories)",
                detail={"own": "allow", "other-app": "deny"})
        return GateVerdict(
            g, Decision.ALLOW,
            f"{setype}: levelFrom=user, so apps of the SAME user share categories and "
            f"are NOT isolated by MLS -- only DAC separates them",
            detail={"own": "allow", "same-user-app": "allow (MLS does not isolate)"})

    # Any other constrained object: we cannot pin its instance level statically, so
    # we do not assert a DENY. Note the caveat for auditors.
    return GateVerdict(
        g, Decision.ALLOW,
        "object is at s0 (readable) or created at the subject's level; MLS isolates "
        "this subject only from other categorised subjects' data (not decided here)")


def _has_categories(subject: Subject) -> bool:
    return subject.level_from in (LevelFrom.APP, LevelFrom.USER, LevelFrom.ALL)
