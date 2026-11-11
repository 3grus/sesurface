"""Render a reach analysis two ways: a traceable report and a JSON cache.

The report is for a human auditor and is meant to be easy on the eyes: a compact
build-identity and subject header, a ranked pivot section (what reaching things
*gives* the subject), then the findings grouped by object class with every gate's
verdict and evidence, and a closing list of the analysis's blind spots. The JSON is
the machine-readable form and the contract the later code-attribution pass consumes.

Rendering uses a small, consistent symbol set (see LEGEND) rather than heavy tables,
so it reads well in a terminal and in a Markdown viewer alike.
"""

from __future__ import annotations

import json
from typing import Any

from .engine import ReachReport
from .pivot import PivotReport
from .types import BackingTier, Decision, Finding, Gate, PivotKind

# Symbols. Kept to a handful so the eye learns them quickly.
_DEC = {Decision.ALLOW: "✓", Decision.DENY: "✗", Decision.NA: "—", Decision.UNKNOWN: "?"}
_TIER = {BackingTier.CONFIRMED: "●", BackingTier.PREDICTED: "○", BackingTier.POLICY_ONLY: "·"}
_GATE_LABEL = {Gate.TE: "TE ", Gate.MLS: "MLS", Gate.DAC: "DAC", Gate.INCODE: "COD"}

BLIND_SPOTS = [
    ("Anonymous binder objects / callback tokens",
     "Binder handles passed inside transactions (not registered with "
     "servicemanager) are created at runtime in code. 'binder call' to the host "
     "domain covers reaching the process, but the specific interface is invisible."),
    ("Abstract-namespace sockets (@name)",
     "They have no filesystem entry, so no DAC, and are created in code; only the "
     "TE connectto to the server domain is visible statically."),
    ("In-code permission checks",
     "Whether a reachable binder service acts on the call depends on its bytecode "
     "(getCallingUid / enforcePermission / AppOps). That is the deferred jadx/ghidra "
     "pass; findings mark the COD gate '?' with a pointer to where to look."),
    ("Runtime /data, runtime-registered services, lazy-HAL state",
     "Only the factory image is analysed; /data contents and services registered "
     "purely in code have no static trace."),
    ("Third-party apps, concrete appIds, runtime grants",
     "App UIDs are assigned at install (runtime). Runtime permission / AppOps / role "
     "grants are assumed granted (worst case) and flagged."),
    ("Bootloader cmdline and setenforce",
     "The bootloader can append to the kernel command line, and a userdebug build "
     "can be set permissive at runtime; only a 'user' build guarantees enforcing."),
]


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #

def to_json(report: ReachReport) -> dict[str, Any]:
    bi = report.model.assembled.identity
    subj = report.subject
    by_class: dict[str, list[dict]] = {}
    for f in report.findings:
        by_class.setdefault(f.tclass, []).append(_finding_json(f))

    return {
        "schema": "sesurface/reach/1",
        "source_domain": subj.domain,
        "build_identity": {
            "system_sdk": bi.system_sdk, "system_release": bi.system_release,
            "vendor_sdk": bi.vendor_sdk, "board_api_level": bi.board_api_level,
            "first_api_level": bi.first_api_level, "policy_vers": bi.policy_vers,
            "build_type": bi.build_type, "skewed": bi.skewed,
            "enforcing_static_guarantee": bi.enforcing_static_guarantee,
        },
        "policy": {
            "method": report.model.assembled.method,
            "reason": report.model.assembled.reason,
            "path": report.model.assembled.path,
        },
        "subject": {
            "uid_class": subj.uid_class.value, "level_from": subj.level_from.value,
            "data_type": subj.data_type, "mls_trusted": subj.is_mls_trusted,
            "permissive": subj.is_permissive,
            "uid": subj.uid, "gids": list(subj.gids), "caps": sorted(subj.caps),
            "provenance": subj.provenance,
        },
        "reached_domains": sorted(report.te.reached_domains),
        "pivots": {
            "becomes": [_pivot_json(p) for p in report.pivots.becomes],
            "attacks": [_pivot_json(p) for p in report.pivots.attacks],
        },
        "counts": {
            "findings": len(report.findings),
            "allowed": sum(1 for f in report.findings if f.allowed),
            "confirmed": sum(1 for f in report.findings
                             if f.backing and f.backing.tier is BackingTier.CONFIRMED),
            "becomes": len(report.pivots.becomes),
            "attacks": len(report.pivots.attacks),
        },
        "findings_by_class": by_class,
    }


def _pivot_json(p) -> dict[str, Any]:
    return {"kind": p.kind.value, "to": p.to_domain, "via": p.via,
            "rank": p.rank, "why": p.rationale, "lockdown": p.lockdown,
            "code": p.code}


def _finding_json(f: Finding) -> dict[str, Any]:
    return {
        "type": f.setype, "class": f.tclass, "perms": sorted(f.perms),
        "allowed": f.allowed, "layers": sorted(f.layers),
        "via_domains": list(f.via_domains),
        "gates": {g.value: {"decision": v.decision.value, "evidence": v.evidence,
                            "detail": v.detail}
                  for g, v in f.gates.items()},
        "xperms": list(f.xperms),
        "backing": None if not f.backing else {
            "tier": f.backing.tier.value, "kind": f.backing.kind,
            "artifacts": f.backing.artifacts, "note": f.backing.note,
        },
        "code_artifacts": f.code_artifacts,
        "code_refs": [{"tool": r.tool, "artifact": r.artifact, "why": r.why}
                      for r in f.code_refs],
    }


# --------------------------------------------------------------------------- #
# Markdown report
# --------------------------------------------------------------------------- #

def render_report(report: ReachReport) -> str:
    bi = report.model.assembled.identity
    subj = report.subject
    L: list[str] = []
    rule = "─" * 60

    L.append(f"# sesurface · surface reachable from `{subj.domain}`")
    L.append("")

    # --- Build identity ----------------------------------------------------- #
    skew = "yes ⚠️" if bi.skewed else "no"
    enf = "yes" if bi.enforcing_static_guarantee else f"not guaranteed ({bi.build_type})"
    L += [
        "## Build identity",
        f"- **Android {bi.system_release}** (SDK {bi.system_sdk}) · vendor SDK "
        f"{bi.vendor_sdk} · policy {bi.policy_vers} · first_api_level {bi.first_api_level}",
        f"- build type `{bi.build_type}` · vendor/system skew: **{skew}** · "
        f"enforcing (static): **{enf}**",
        f"- policy: **{report.model.assembled.method}** — {report.model.assembled.reason}",
    ]
    if report.te.permissive_note:
        L.append(f"- ⚠️ {report.te.permissive_note}")
    L.append("")

    # --- Subject ------------------------------------------------------------ #
    L += [
        "## Subject",
        f"`{subj.domain}` · uid **{subj.uid_class.value}** · levelFrom "
        f"**{subj.level_from.value}** · mlstrustedsubject **{subj.is_mls_trusted}** · "
        f"permissive **{subj.is_permissive}**",
    ]
    # Concrete native-daemon identity (resolved from init `.rc`), when known.
    if subj.uid is not None or subj.gids or subj.caps:
        uid_s = str(subj.uid) if subj.uid is not None else "?"
        gids_s = ", ".join(str(g) for g in subj.gids) if subj.gids else "none"
        caps_s = ", ".join(sorted(subj.caps)) if subj.caps else "none"
        L.append(f"- concrete identity: uid **{uid_s}** · gids **{gids_s}** · "
                 f"capabilities **{caps_s}**")
    for pr in subj.provenance:
        L.append(f"  - {pr}")
    L.append("")

    # --- Summary ------------------------------------------------------------ #
    allowed = sum(1 for f in report.findings if f.allowed)
    confirmed = sum(1 for f in report.findings
                    if f.backing and f.backing.tier is BackingTier.CONFIRMED)
    L += [
        "## Summary",
        f"- **{len(report.findings)}** reachable objects · **{allowed}** pass all "
        f"gates · **{confirmed}** backed by a concrete image artifact",
        f"- pivots: **{len(report.pivots.becomes)}** BECOMES · "
        f"**{len(report.pivots.attacks)}** ATTACKS",
        f"- reached domains (via exec transitions): "
        f"{', '.join('`'+d+'`' for d in sorted(report.te.reached_domains)) or '(none)'}",
        "",
    ]

    # --- Pivots ------------------------------------------------------------- #
    L += _render_pivots(report.pivots)

    # --- Legend ------------------------------------------------------------- #
    L += [
        "## Findings",
        f"Legend — gates: {_DEC[Decision.ALLOW]} allow  {_DEC[Decision.DENY]} deny  "
        f"{_DEC[Decision.NA]} n/a  {_DEC[Decision.UNKNOWN]} unknown · "
        f"backing: {_TIER[BackingTier.CONFIRMED]} confirmed  "
        f"{_TIER[BackingTier.PREDICTED]} predicted  {_TIER[BackingTier.POLICY_ONLY]} policy-only",
        "",
    ]

    # --- Findings by class -------------------------------------------------- #
    by_class: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_class.setdefault(f.tclass, []).append(f)
    for tclass in sorted(by_class):
        fs = by_class[tclass]
        nconf = sum(1 for f in fs
                    if f.backing and f.backing.tier is BackingTier.CONFIRMED)
        L.append(f"### {tclass}  ·  {len(fs)} object(s), {nconf} confirmed")
        L.append("")
        for f in fs:
            L.append(_render_finding(f))
            L.append("")

    # --- Blind spots -------------------------------------------------------- #
    L.append("## What this static analysis does NOT cover")
    for title, text in BLIND_SPOTS:
        L.append(f"- **{title}** — {text}")

    return "\n".join(L) + "\n"


def _render_pivots(pivots: PivotReport) -> list[str]:
    if not pivots.becomes and not pivots.attacks:
        return ["## Pivots", "_None found._", ""]
    L = ["## Pivots — what reaching these *gives* the subject", ""]
    cap = 25
    if pivots.becomes:
        L.append("### ★ BECOMES — run code as a new domain, no further bug needed")
        for p in pivots.becomes[:cap]:
            L.append(f"- → **`{p.to_domain}`**  ·  {p.via}")
            L.append(f"    - {p.rationale}")
            if p.code:
                L.append(f"    - 🔍 code: {', '.join('`'+c+'`' for c in p.code[:3])}")
            if p.lockdown:
                L.append(f"    - 🔒 lockdown: `{p.lockdown}`")
        _tail(L, pivots.becomes, cap)
        L.append("")
    if pivots.attacks:
        L.append("### ⚡ ATTACKS — feed input to a domain; a bug there escalates "
                 "(ranked, most severe first)")
        for p in pivots.attacks[:cap]:
            L.append(f"- ~> **`{p.to_domain}`**  ·  {p.via}  _(rank {p.rank})_")
            L.append(f"    - {p.rationale}")
            if p.code:
                L.append(f"    - 🔍 code: {', '.join('`'+c+'`' for c in p.code[:3])}")
            if p.lockdown:
                L.append(f"    - 🔒 lockdown: `{p.lockdown}`")
        _tail(L, pivots.attacks, cap)
        L.append("")
    return L


def _tail(L: list[str], items: list, cap: int) -> None:
    """Add a collapsed '+N more' line when a list was truncated (full set is in JSON)."""
    if len(items) > cap:
        extra = items[cap:]
        names = ", ".join(f"`{p.to_domain}`" for p in extra[:12])
        more = f" … and {len(extra) - 12} others" if len(extra) > 12 else ""
        L.append(f"- _+{len(extra)} more (see JSON): {names}{more}_")


def _render_finding(f: Finding) -> str:
    tier = _TIER[f.backing.tier] if f.backing else " "
    perms = " ".join(sorted(f.perms)) if f.perms else "(xperm/none)"
    blocked = "" if f.allowed else "  ✗ blocked"
    layers = ",".join(sorted(f.layers))
    lines = [f"{tier} **`{f.setype}`** — `{perms}` — _{layers}_{blocked}"]
    for g in (Gate.TE, Gate.MLS, Gate.DAC, Gate.INCODE):
        v = f.gates.get(g)
        if v is None:
            continue
        lines.append(f"    {_DEC[v.decision]} {_GATE_LABEL[g]}  {v.evidence}")
    if f.backing:
        b = f.backing
        arts = ", ".join(f"`{a}`" for a in b.artifacts[:4])
        more = f" (+{len(b.artifacts) - 4})" if len(b.artifacts) > 4 else ""
        lines.append(f"    · backing  {b.tier.value}/{b.kind}: {arts or '—'}{more}")
    if f.code_artifacts:
        lines.append(f"    · code     {', '.join('`'+c+'`' for c in f.code_artifacts[:4])}")
    return "\n".join(lines)
