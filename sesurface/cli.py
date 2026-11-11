"""Command-line entry point for sesurface.

Subcommands (built out across the implementation phases):

  doctor       Check the environment and report which analysis layers are available.
  build-image  Build and cache the source-independent image + policy model (stage A/B).
  reach        Enumerate the surface reachable from one or more source domains.
  locate       Map already-computed findings to the code that handles them (stage G).

Only `doctor` is wired up in phase 1; the others are registered with clear
"not implemented yet" stubs so the CLI shape is visible and stable from the start.
"""

from __future__ import annotations

import argparse
import sys

import json
import os

from . import __version__
from .doctor import run_doctor, format_report


def _default_work_dir(root: str) -> str:
    """Where to put carved partitions, the assembled policy and the cache.

    A sibling `.sesurface-cache/` next to the image keeps everything for one image
    together and out of the project tree (it is git-ignored).
    """
    return os.path.join(os.path.dirname(os.path.abspath(root.rstrip("/"))),
                        ".sesurface-cache")


def _cmd_doctor(args: argparse.Namespace) -> int:
    rep = run_doctor()
    print(format_report(rep))
    # Exit non-zero when core analysis is blocked, so scripts/CI can gate on it.
    return 0 if rep.core_ok else 1


def _cmd_build_image(args: argparse.Namespace) -> int:
    from .engine import build_image_model
    work = args.work or _default_work_dir(args.root)
    print(f"Building image model for {args.root} (cache: {work}) ...", file=sys.stderr)
    model = build_image_model(args.root, work, use_cache=not args.no_cache)
    bi = model.assembled.identity
    print(f"  partitions : {', '.join(sorted(model.partitions.partitions))}")
    print(f"  inodes     : {len(model.inodes.meta)} ({len(model.inodes.by_type)} types)")
    print(f"  policy     : {model.assembled.method} — {model.assembled.reason}")
    print(f"  identity   : system SDK {bi.system_sdk} / vendor SDK {bi.vendor_sdk} / "
          f"policy {bi.policy_vers} / {bi.build_type} / skew={bi.skewed}")
    for n in model.partitions.notes:
        print(f"  note       : {n}")
    return 0


def _cmd_reach(args: argparse.Namespace) -> int:
    from .engine import build_image_model, run_reach
    from .report import render_report, to_json
    work = args.work or _default_work_dir(args.root)
    model = build_image_model(args.root, work, use_cache=not args.no_cache)
    policy = model.open_policy()   # Loaded once, reused across all source domains.

    domains = [d.strip() for d in args.source.split(",") if d.strip()]
    for domain in domains:
        if not policy.is_type(domain):
            print(f"warning: '{domain}' is not a type in this policy; skipping.",
                  file=sys.stderr)
            continue
        report = run_reach(model, policy, domain,
                           follow_transitions=not args.no_transitions)
        n = len(report.findings)
        allowed = sum(1 for f in report.findings if f.allowed)
        print(f"{domain}: {n} reachable objects ({allowed} not gate-blocked), "
              f"{len(report.te.reached_domains)} reached domains.", file=sys.stderr)

        suffix = domain if len(domains) > 1 else ""
        if args.report:
            path = _with_suffix(args.report, suffix)
            with open(path, "w") as f:
                f.write(render_report(report))
            print(f"  report -> {path}", file=sys.stderr)
        if args.json:
            path = _with_suffix(args.json, suffix)
            with open(path, "w") as f:
                json.dump(to_json(report), f, indent=2)
            print(f"  json   -> {path}", file=sys.stderr)
        if not args.report and not args.json:
            # No output file requested: print the report to stdout.
            print(render_report(report))
    return 0


def _with_suffix(path: str, suffix: str) -> str:
    """Insert `-suffix` before the extension when analysing multiple domains."""
    if not suffix:
        return path
    base, ext = os.path.splitext(path)
    return f"{base}-{suffix}{ext}"


def _cmd_locate(args: argparse.Namespace) -> int:
    """Turn a reach JSON into a code worklist grouped by tool.

    This is the handoff to the deferred ghidra/jadx attribution pass: it collects
    every code artifact the reach analysis pointed at (from findings and pivots),
    de-duplicates them, and groups by the tool to open them with -- so the next pass
    gets a precise, ordered list instead of a whole firmware image.
    """
    with open(args.json) as f:
        data = json.load(f)

    # artifact -> (tool, set of objects/domains it handles).
    by_tool: dict[str, dict[str, set]] = {}

    def add(code_entry: str, handles: str) -> None:
        if ":" not in code_entry:
            return
        tool, artifact = code_entry.split(":", 1)
        tool, artifact = tool.strip(), artifact.strip()
        by_tool.setdefault(tool, {}).setdefault(artifact, set()).add(handles)

    for tclass, items in data.get("findings_by_class", {}).items():
        for fnd in items:
            for ce in fnd.get("code_artifacts", []):
                add(ce, f"{fnd['type']}:{tclass}")
    for kind in ("becomes", "attacks"):
        for p in data.get("pivots", {}).get(kind, []):
            for ce in p.get("code", []):
                add(ce, f"{kind}->{p['to']}")

    print(f"# Code worklist for `{data.get('source_domain')}`  "
          f"(from {args.json})\n")
    order = ["jadx", "ghidra", "kernel", "init"]
    for tool in order + [t for t in by_tool if t not in order]:
        arts = by_tool.get(tool)
        if not arts:
            continue
        print(f"## {tool}  ({len(arts)} artifact(s))")
        for artifact in sorted(arts):
            handles = sorted(arts[artifact])
            shown = ", ".join(handles[:6]) + (f" (+{len(handles) - 6})"
                                              if len(handles) > 6 else "")
            print(f"  - {artifact}\n      handles: {shown}")
        print()
    return 0


def _cmd_attribute(args: argparse.Namespace) -> int:
    """Stage H: resolve the in-code (COD) gate by decompiling the handler.

    Consumes the in-memory model directly (not the flattened JSON), so it has the
    structured `CodeRef.why`, the `xperms`, `backing.artifacts`, and can pull the
    exact binaries out of the image with `ImageFiles.extract_to`.
    """
    from .engine import build_image_model, run_reach
    from .locate import CodeLocator
    from .model.extract import ImageFiles
    from .model.initrc import DomainServiceMap
    from .attribute import attribute_findings
    from .report import to_json
    from .types import Gate

    work = args.work or _default_work_dir(args.root)
    model = build_image_model(args.root, work, use_cache=not args.no_cache)
    policy = model.open_policy()
    if not policy.is_type(args.source):
        print(f"error: '{args.source}' is not a type in this policy.", file=sys.stderr)
        return 1

    report = run_reach(model, policy, args.source,
                       follow_transitions=not args.no_transitions)
    dsmap = DomainServiceMap(model.initrc, policy, model.contexts)
    locator = CodeLocator(policy, model.inodes, model.contexts, dsmap=dsmap,
                          vintf=model.vintf, appdomains=model.appdomains)

    findings = report.findings
    if args.target:
        needles = [t.strip() for t in args.target.split(",") if t.strip()]
        findings = [f for f in findings
                    if any(n in f.setype or n in f.tclass for n in needles)]
        if not findings:
            print(f"no findings match target(s): {args.target}", file=sys.stderr)
            return 1

    scratch = args.scratch or os.path.join(work, "attrib")
    files = ImageFiles(model.partitions)
    try:
        results = attribute_findings(model, locator, files, findings, scratch,
                                     use_ghidra=args.ghidra,
                                     only_targets=not args.all)
    finally:
        files.close()

    print(f"# Code-attribution for `{args.source}`  "
          f"({len(results)} finding(s) attributed)\n", file=sys.stderr)
    tally: dict[str, int] = {}
    for a in results:
        tally[a.attribution] = tally.get(a.attribution, 0) + 1
    for a in results:
        glyph = {"open": "OPEN ", "gated": "GATED", "kernel": "KERN ",
                 "latent": "LATNT", "skipped": "SKIP ",
                 "unresolved": "UNRES", "aggregate": "AGGR "}.get(a.attribution, "?????")
        print(f"[{glyph}] {a.setype}:{a.tclass}")
        if a.handler:
            print(f"         handler : {a.handler}")
        if a.artifact:
            print(f"         in      : {a.artifact}  ({a.tool})")
        if a.caller_check != "n/a":
            print(f"         caller  : check {a.caller_check}"
                  + (f"  [{', '.join(c.split('(')[0].split('::')[-1] for c in a.checks[:5])}]"
                     if a.checks else ""))
        if a.ioctls:
            print(f"         ioctls  : {len(a.ioctls)} -> "
                  + "; ".join(a.ioctls[:6]) + (" ..." if len(a.ioctls) > 6 else ""))
        if a.coverage:
            c = a.coverage
            print(f"         txns    : {sum(c.values())} "
                  f"({c.get('gated', 0)} gated, {c.get('ungated', 0)} ungated, "
                  f"{c.get('needs-review', 0)} needs-review, "
                  f"{c.get('not-attempted', 0)} not-attempted)")
            ung = [t for t in a.transactions if t.get("status") == "ungated"]
            if ung:
                sample = ", ".join(
                    t.get("method", "")
                    + (f"#{t['code']}" if t.get("code") is not None else "")
                    + (f"@{t['service']}" if t.get("service") else "")
                    for t in ung[:6])
                print(f"         ungated : {sample}" + (" ..." if len(ung) > 6 else ""))
        print(f"         method  : {a.method} (confidence {a.confidence}) "
              f"· status: {a.resolution()}")
        if a.notes:
            print(f"         note    : {a.notes}")
        incode = next((f for f in findings
                       if f.setype == a.setype and f.tclass == a.tclass), None)
        if incode is not None:
            print(f"         COD gate: {incode.gates[Gate.INCODE].decision.value}")
        print()
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(tally.items())),
          file=sys.stderr)
    # Coverage ledger: what a reviewer can trust vs what still needs human analysis.
    ledger: dict[str, int] = {}
    for a in results:
        ledger[a.resolution()] = ledger.get(a.resolution(), 0) + 1
    order = ["decided", "needs-review", "not-attempted", "unresolved", "n/a"]
    parts = [f"{k}={ledger[k]}" for k in order if k in ledger]
    outstanding = sum(ledger.get(k, 0) for k in
                      ("needs-review", "not-attempted", "unresolved"))
    print(f"coverage: {', '.join(parts)}  ({outstanding} of {len(results)} still "
          "need analysis)", file=sys.stderr)
    # Framework (jadx) per-transaction ledger -- the deliverable for "what is
    # actually reachable" behind the system_server binder surface.
    txn: dict[str, int] = {}
    nsvc = 0
    for a in results:
        if a.coverage:
            nsvc += 1
            for k, v in a.coverage.items():
                txn[k] = txn.get(k, 0) + v
    if txn:
        total = sum(txn.values())
        decided = txn.get("gated", 0) + txn.get("ungated", 0)
        print(f"framework: {total} transactions across {nsvc} service finding(s) -- "
              f"{txn.get('gated', 0)} gated, {txn.get('ungated', 0)} ungated "
              f"(actionable), {decided} decided, {txn.get('needs-review', 0)} "
              f"needs-review, {txn.get('not-attempted', 0)} not-attempted",
              file=sys.stderr)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(to_json(report), f, indent=2)
        print(f"  augmented json -> {args.json}", file=sys.stderr)
    return 0


def _cmd_stub(args: argparse.Namespace) -> int:
    print(f"'{args._name}' is not implemented yet (planned for a later phase).",
          file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="sesurface",
        description="Enumerate the object surface an Android SELinux subject can reach.",
    )
    ap.add_argument("--version", action="version", version=f"sesurface {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="check the environment and report capabilities")
    d.set_defaults(func=_cmd_doctor)

    # --- Stubs for the stages still to come. Keeping their flags here documents --
    # --- the intended interface even before the implementation lands. -----------
    bi = sub.add_parser("build-image",
                        help="build+cache the source-independent image/policy model")
    bi.add_argument("-r", "--root", required=True,
                    help="directory of raw partition images (system.img, vendor.img, ...)")
    bi.add_argument("--work", help="work/cache directory (default: .sesurface-cache next to the image)")
    bi.add_argument("--no-cache", action="store_true", help="rebuild even if a cache exists")
    bi.set_defaults(func=_cmd_build_image)

    rc = sub.add_parser("reach", help="enumerate surface reachable from a source domain")
    rc.add_argument("-r", "--root", required=True,
                    help="directory of raw partition images (system.img, vendor.img, ...)")
    rc.add_argument("-s", "--source", required=True,
                    help="source domain(s), comma-separated, e.g. untrusted_app,hal_camera_default")
    rc.add_argument("--report", help="write the human-readable traceable report here (.md)")
    rc.add_argument("--json", help="write the machine-readable JSON cache here (.json)")
    rc.add_argument("--work", help="work/cache directory (default: .sesurface-cache next to the image)")
    rc.add_argument("--no-cache", action="store_true", help="rebuild the image model even if cached")
    rc.add_argument("--no-transitions", action="store_true",
                    help="do not follow process-transition (BECOMES) pivots")
    rc.set_defaults(func=_cmd_reach)

    lo = sub.add_parser("locate",
                        help="turn a reach JSON into a ghidra/jadx code worklist")
    lo.add_argument("--json", required=True, help="a reach JSON produced by `reach`")
    lo.set_defaults(func=_cmd_locate)

    at = sub.add_parser("attribute",
                        help="stage H: decompile handlers and resolve the in-code (COD) gate")
    at.add_argument("-r", "--root", required=True,
                    help="directory of raw partition images (system.img, vendor.img, ...)")
    at.add_argument("-s", "--source", required=True,
                    help="source domain to attribute (single domain)")
    at.add_argument("--target",
                    help="only attribute findings whose setype/class matches these "
                         "comma-separated substrings (e.g. audioserver,mapper,binder_device)")
    at.add_argument("--ghidra", action="store_true",
                    help="deepen ELF-symbol results with a Ghidra headless call-site pass")
    at.add_argument("--all", action="store_true",
                    help="also list classes with no in-code gate (skipped by default)")
    at.add_argument("--json", help="write the COD-augmented reach JSON here")
    at.add_argument("--scratch", help="isolated dir for extracted binaries (default: <work>/attrib)")
    at.add_argument("--work", help="work/cache directory (default: .sesurface-cache next to the image)")
    at.add_argument("--no-cache", action="store_true", help="rebuild the image model even if cached")
    at.add_argument("--no-transitions", action="store_true",
                    help="do not follow process-transition (BECOMES) pivots")
    at.set_defaults(func=_cmd_attribute)

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
