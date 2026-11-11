#!/usr/bin/env python3
"""Compare two sesurface `reach` JSONs and report what moved.

Purpose
-------
sesurface's analysis is meant to get *more precise* as we teach it new facts (init
`.rc`, `ueventd.rc`, VINTF). "More precise" has a specific, measurable shape, and
this script makes it visible so an enrichment pass can be judged honestly instead
of by vibes:

  * Fewer DAC verdicts stuck at `?` (unknown) once device-node ownership is known.
  * More findings `confirmed` (tied to a concrete image artifact) rather than
    merely predicted.
  * Subjects whose uid / caps / data-type actually resolve (HAL daemons, native
    services) instead of falling back to defaults.
  * Fewer unresolved host placeholders (`(host of X)`) in the code pointers.

Reading the numbers correctly
------------------------------
Counts alone can mislead. Enrichment *should* turn some DAC `?` into a hard `✗`
(deny) once we know a device node is root-owned 0600 and the subject is not root.
That legitimately REMOVES an object from the "passes all gates" set. That is a
precision win, not a regression. So this tool separates two very different things:

  * "unknown resolved"  -- a gate that was `?` is now a real decision. Always good.
  * "allowed -> blocked on a CONFIRMED object" -- an object we are sure exists in
    the image flipped from reachable to blocked. THIS is the one to eyeball: it is
    usually a correct tightening, but it is also exactly what a bug would look like,
    so we list each one by name rather than burying it in a count.

Usage
-----
    python scripts/benchmark.py BEFORE.json AFTER.json
    python scripts/benchmark.py --snapshot    # just print one JSON's metrics

Exit status is 0 always; this is a reporting tool, not a gate. The human reads the
"needs a look" section and decides.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter


# --------------------------------------------------------------------------- #
# Metric extraction -- everything we measure comes straight out of the JSON the
# `reach` command already writes, so the benchmark adds no new analysis of its own.
# --------------------------------------------------------------------------- #

def _iter_findings(doc: dict):
    """Yield every finding, flattened across the per-class grouping in the JSON."""
    for tclass, items in doc.get("findings_by_class", {}).items():
        for f in items:
            yield f


def _finding_id(f: dict) -> str:
    """A stable identity for a finding so we can match it across two runs.

    (type, class) is the object; two findings with the same pair are the same
    surface element even if their gate verdicts changed between runs.
    """
    return f"{f.get('type')}:{f.get('class')}"


def _gate_decision(f: dict, gate: str) -> str | None:
    """The decision string ('allow'/'deny'/'na'/'unknown') for one gate, or None."""
    g = f.get("gates", {}).get(gate)
    return g.get("decision") if g else None


def metrics(doc: dict) -> dict:
    """Collapse one reach JSON into the scalar numbers we track across runs."""
    findings = list(_iter_findings(doc))

    dac = Counter(_gate_decision(f, "dac") or "absent" for f in findings)
    confirmed = sum(1 for f in findings
                    if (f.get("backing") or {}).get("tier") == "confirmed")

    # Unresolved host placeholders left in the code pointers -- a direct count of
    # the "we could not name the binary behind this service" gap that VINTF /
    # init `.rc` resolution is meant to close.
    # A service/hwservice whose hosting code we could not name is rendered with a
    # placeholder artifact: "(host of X)" (old) or "(in-process HAL: X)" (new, when we
    # could at least characterise why). Both mean "no concrete host binary", so we
    # count either and the before/after delta stays comparable.
    _UNRESOLVED_MARKERS = ("(host of", "(in-process HAL", "(no provider")
    unresolved_hosts = 0
    for f in findings:
        for ce in f.get("code_artifacts", []):
            if any(mk in ce for mk in _UNRESOLVED_MARKERS):
                unresolved_hosts += 1

    subj = doc.get("subject", {})
    counts = doc.get("counts", {})
    return {
        "source_domain": doc.get("source_domain"),
        "findings": len(findings),
        "allowed": counts.get("allowed", sum(1 for f in findings if f.get("allowed"))),
        "confirmed": confirmed,
        "dac": dict(dac),
        "unresolved_hosts": unresolved_hosts,
        "subject": {
            "uid_class": subj.get("uid_class"),
            "data_type": subj.get("data_type"),
            "mls_trusted": subj.get("mls_trusted"),
            "provenance_lines": len(subj.get("provenance", []) or []),
        },
        "becomes": counts.get("becomes"),
        "attacks": counts.get("attacks"),
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _fmt_delta(before: int | None, after: int | None) -> str:
    """'before -> after (+/-N)', tolerant of missing values."""
    if before is None and after is None:
        return "—"
    if before is None:
        return f"(new) {after}"
    if after is None:
        return f"{before} (gone)"
    d = after - before
    arrow = "" if d == 0 else f"  ({'+' if d > 0 else ''}{d})"
    return f"{before} -> {after}{arrow}"


def print_snapshot(doc: dict) -> None:
    m = metrics(doc)
    print(f"# reach metrics for `{m['source_domain']}`\n")
    print(f"  findings         : {m['findings']}")
    print(f"  allowed (gates)  : {m['allowed']}")
    print(f"  confirmed backing: {m['confirmed']}")
    print(f"  unresolved hosts : {m['unresolved_hosts']}")
    print(f"  pivots           : {m['becomes']} becomes / {m['attacks']} attacks")
    print(f"  DAC decisions    : {m['dac']}")
    print(f"  subject          : uid={m['subject']['uid_class']} "
          f"data_type={m['subject']['data_type']} "
          f"mls_trusted={m['subject']['mls_trusted']} "
          f"provenance={m['subject']['provenance_lines']} line(s)")


def diff(before: dict, after: dict) -> int:
    mb, ma = metrics(before), metrics(after)
    if mb["source_domain"] != ma["source_domain"]:
        print(f"warning: comparing different domains "
              f"({mb['source_domain']} vs {ma['source_domain']})", file=sys.stderr)

    print(f"# benchmark: `{mb['source_domain']}`  (before -> after)\n")

    print("## headline")
    print(f"  findings          : {_fmt_delta(mb['findings'], ma['findings'])}")
    print(f"  allowed (gates)   : {_fmt_delta(mb['allowed'], ma['allowed'])}")
    print(f"  confirmed backing : {_fmt_delta(mb['confirmed'], ma['confirmed'])}")
    print(f"  unresolved hosts  : {_fmt_delta(mb['unresolved_hosts'], ma['unresolved_hosts'])}")
    print(f"  pivots (becomes)  : {_fmt_delta(mb['becomes'], ma['becomes'])}")
    print(f"  pivots (attacks)  : {_fmt_delta(mb['attacks'], ma['attacks'])}")

    print("\n## DAC decision histogram (the gate the init/ueventd work targets)")
    keys = sorted(set(mb["dac"]) | set(ma["dac"]))
    for k in keys:
        print(f"  {k:8s}: {_fmt_delta(mb['dac'].get(k), ma['dac'].get(k))}")

    print("\n## subject resolution")
    for field in ("uid_class", "data_type", "mls_trusted", "provenance_lines"):
        b, a = mb["subject"][field], ma["subject"][field]
        mark = "" if b == a else "   <-- changed"
        print(f"  {field:16s}: {b} -> {a}{mark}")

    # --- The honest part: per-gate transitions, split into good vs needs-a-look.
    _transition_report(before, after)
    return 0


def _transition_report(before: dict, after: dict) -> None:
    """Classify how each finding's gates moved, matched by (type,class).

    We care about two buckets:
      * unknowns that became real decisions  -- the precision win we want
      * confirmed objects that went allowed -> blocked -- correct tightening is
        indistinguishable from a bug by count alone, so we name each one
    """
    b_idx = {_finding_id(f): f for f in _iter_findings(before)}
    a_idx = {_finding_id(f): f for f in _iter_findings(after)}

    resolved_unknowns = Counter()      # gate -> count of ? that became a decision
    allowed_to_blocked_confirmed: list[str] = []
    allowed_to_blocked_other: list[str] = []
    blocked_to_allowed: list[str] = []

    for fid, fa in a_idx.items():
        fb = b_idx.get(fid)
        if fb is None:
            continue
        for gate in ("te", "mls", "dac", "incode"):
            db, da = _gate_decision(fb, gate), _gate_decision(fa, gate)
            if db == "unknown" and da in ("allow", "deny", "na"):
                resolved_unknowns[gate] += 1

        if fb.get("allowed") and not fa.get("allowed"):
            tier = (fa.get("backing") or {}).get("tier")
            (allowed_to_blocked_confirmed if tier == "confirmed"
             else allowed_to_blocked_other).append(fid)
        elif not fb.get("allowed") and fa.get("allowed"):
            blocked_to_allowed.append(fid)

    print("\n## gate precision (good: unknowns resolved into real decisions)")
    if resolved_unknowns:
        for gate, n in sorted(resolved_unknowns.items()):
            print(f"  {gate.upper():6s}: {n} unknown verdict(s) now resolved")
    else:
        print("  (none)")

    print("\n## needs a look: findings that flipped allowed -> blocked")
    if allowed_to_blocked_confirmed:
        print(f"  on CONFIRMED objects ({len(allowed_to_blocked_confirmed)}) -- "
              f"usually a correct tightening, verify none is a bug:")
        for fid in sorted(allowed_to_blocked_confirmed)[:40]:
            print(f"    - {fid}")
        if len(allowed_to_blocked_confirmed) > 40:
            print(f"    ... (+{len(allowed_to_blocked_confirmed) - 40} more)")
    if allowed_to_blocked_other:
        print(f"  on predicted/policy-only objects: {len(allowed_to_blocked_other)} "
              f"(lower stakes; the object may not exist at runtime anyway)")
    if not allowed_to_blocked_confirmed and not allowed_to_blocked_other:
        print("  (none)")

    if blocked_to_allowed:
        print(f"\n## note: {len(blocked_to_allowed)} finding(s) went blocked -> allowed")
        print("  (a gate that was denying now permits; confirm that is intended)")
        for fid in sorted(blocked_to_allowed)[:20]:
            print(f"    - {fid}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Compare two sesurface reach JSONs (before/after an enrichment).")
    ap.add_argument("before", help="baseline reach JSON")
    ap.add_argument("after", nargs="?",
                    help="new reach JSON; omit with --snapshot to just dump metrics")
    ap.add_argument("--snapshot", action="store_true",
                    help="print metrics for a single JSON instead of diffing")
    args = ap.parse_args(argv)

    with open(args.before) as f:
        before = json.load(f)
    if args.snapshot or not args.after:
        print_snapshot(before)
        return 0
    with open(args.after) as f:
        after = json.load(f)
    return diff(before, after)


if __name__ == "__main__":
    raise SystemExit(main())
