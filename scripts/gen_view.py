#!/usr/bin/env python3
"""Build the Reachable Surface Explorer view for one source domain.

Runs the reach + code-attribution pipeline for a subject against an unpacked image
and emits a distilled JSON of the results (summary, per-class surface, the framework
per-service/per-transaction COD ledger, and the native/ioctl verdicts). With
``--html`` it also injects that JSON into ``scripts/reach-view.html`` to produce a
single self-contained HTML page an analyst can open and filter.

Usage:
    uv run python scripts/gen_view.py untrusted_app \
        -r images/aosp-api33-x86_64/x86_64 \
        --work images/aosp-api33-x86_64/cache \
        --json out/view-untrusted_app.json \
        --html out/view-untrusted_app.html

The decompile of services.jar/framework.jar (via jadx) is cached under the work dir,
so the first run is slow and later runs are quick. Run `sesurface doctor` first to
confirm jadx is available; without it the framework half is reported as unresolved.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys

from sesurface.engine import build_image_model, run_reach
from sesurface.locate import CodeLocator
from sesurface.model.extract import ImageFiles
from sesurface.model.initrc import DomainServiceMap
from sesurface.attribute import attribute_findings, Attributor
from sesurface.types import Gate

_TEMPLATE = os.path.join(os.path.dirname(__file__), "reach-view.html")


def build_view(root: str, work: str, source: str, use_cache: bool = True) -> dict:
    """Run the pipeline and return the distilled view document."""
    model = build_image_model(root, work, use_cache=use_cache)
    policy = model.open_policy()
    if not policy.is_type(source):
        raise SystemExit(f"error: '{source}' is not a type in this policy.")

    report = run_reach(model, policy, source, follow_transitions=True)
    dsmap = DomainServiceMap(model.initrc, policy, model.contexts)
    locator = CodeLocator(policy, model.inodes, model.contexts, dsmap=dsmap,
                          vintf=model.vintf, appdomains=model.appdomains)
    findings = report.findings

    scratch = os.path.join(work, "attrib")
    files = ImageFiles(model.partitions)
    try:
        results = attribute_findings(model, locator, files, findings, scratch,
                                     use_ghidra=False, only_targets=True)
        # Per-service framework breakdown (the aggregate finding only carries totals).
        attr = Attributor(model, locator, files, scratch)
        fa, _reason = attr._framework()
        services = []
        if fa is not None:
            for cod in fa.analyze_all():
                services.append({
                    "service": cod.service, "interface": cod.interface,
                    "impl_class": cod.impl_class, "impl_file": cod.impl_file,
                    "impl_jar": cod.impl_jar,
                    "note": cod.note, "counts": cod.counts(),
                    "transactions": [
                        {"code": t.code, "method": t.method, "status": t.status,
                         "via": t.via, "permissions": t.permissions}
                        for t in cod.transactions],
                })
    finally:
        files.close()

    # Reachable surface by class, with the in-code (COD) decision tallied.
    classes: dict[str, dict] = {}
    for f in findings:
        c = classes.setdefault(f.tclass, {"class": f.tclass, "n": 0, "cod": {}})
        c["n"] += 1
        v = f.gates.get(Gate.INCODE)
        d = v.decision.value if v else "n/a"
        c["cod"][d] = c["cod"].get(d, 0) + 1
    class_rows = sorted(classes.values(), key=lambda x: -x["n"])

    # Native (non-framework) attribution rows.
    native = []
    for a in results:
        if a.method == "jadx" or a.attribution == "skipped":
            continue
        native.append({
            "setype": a.setype, "tclass": a.tclass, "attribution": a.attribution,
            "handler": a.handler, "artifact": a.artifact, "tool": a.tool,
            "caller_check": a.caller_check, "checks": a.checks[:6],
            "ioctls": a.ioctls[:8], "method": a.method, "confidence": a.confidence,
            "resolution": a.resolution(), "notes": a.notes})

    coverage: dict[str, int] = {}
    for a in results:
        coverage[a.resolution()] = coverage.get(a.resolution(), 0) + 1
    fw_tot = {"gated": 0, "ungated": 0, "needs-review": 0, "not-attempted": 0}
    for s in services:
        for k, v in s["counts"].items():
            fw_tot[k] = fw_tot.get(k, 0) + v

    # Pivots -- the blast radius: where owning the subject leads (BECOMES: run code as
    # a new domain) and what its code it can attack (ATTACKS: feed input to a domain
    # whose bug would escalate). Each target is resolved to the on-disk code to open.
    app_domains = policy.expand("appdomain")
    # Kernel-ioctl detail (driver handler, decoded commands, where the code lives),
    # keyed by device setype, so a "can attack kernel" pivot can carry it.
    _ksym_re = re.compile(r"\[kallsyms:[^\]]*\]")
    ioctl_detail = {}
    for n in native:
        if n["tclass"] in ("chr_file", "blk_file") and n["attribution"] == "kernel":
            km = _ksym_re.search(n["notes"] or "")
            ioctl_detail[n["setype"]] = {
                "handler": n["handler"], "artifact": n["artifact"],
                "ioctls": n["ioctls"], "notes": n["notes"],
                "ksym": km.group(0) if km else ""}
    _via_type = re.compile(r"ioctl on (\S+) ")

    def _pivot_code(p):
        arts = list(p.code)
        if not arts and p.to_domain != "kernel":
            arts = [f"{r.tool}: {r.artifact}" for r in locator.locate_domain(p.to_domain)]
        out = []
        seen = set()
        for a in arts:
            tool, _sep, path = a.partition(": ")
            key = (tool.strip(), path.strip())
            if key in seen:
                continue
            seen.add(key)
            out.append({"tool": tool.strip(), "path": path.strip()})
        return out

    def _pivot(p, kind):
        d = {"kind": kind, "to": p.to_domain, "via": p.via,
             "rationale": p.rationale, "rank": p.rank, "lockdown": p.lockdown,
             "escalates": p.to_domain not in app_domains,
             "code": _pivot_code(p)}
        if p.to_domain == "kernel":
            mt = _via_type.search(p.via)
            if mt and mt.group(1) in ioctl_detail:
                d["ioctl"] = ioctl_detail[mt.group(1)]
        return d

    pivots = {
        "becomes": [_pivot(p, "becomes") for p in report.pivots.becomes],
        "attacks": [_pivot(p, "attacks") for p in report.pivots.attacks],
    }

    return {
        "source": source,
        "generated": datetime.date.today().isoformat(),
        "image": os.path.basename(os.path.dirname(root.rstrip("/"))) or root,
        "totals": {"findings": len(findings), "attributed": len(results),
                   "reached_domains": len(report.te.reached_domains)},
        "classes": class_rows,
        "coverage": coverage,
        "framework": {"services": services, "totals": fw_tot,
                      "n_services": len(services)},
        "native": native,
        "pivots": pivots,
    }


def render_html(view: dict, template_path: str = _TEMPLATE) -> str:
    """Inject the view JSON into the HTML template, producing a standalone page."""
    with open(template_path) as f:
        tpl = f.read()
    if "__DATA__" not in tpl:
        raise SystemExit(f"template {template_path} has no __DATA__ placeholder")
    # Escape `<` so the payload cannot close the surrounding <script> tag.
    payload = json.dumps(view, separators=(",", ":")).replace("<", "\\u003c")
    return tpl.replace("__DATA__", payload)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", help="source SELinux domain (e.g. untrusted_app)")
    ap.add_argument("-r", "--root", default="images/aosp-api33-x86_64/x86_64",
                    help="unpacked image root (the x86_64/ subdir)")
    ap.add_argument("--work", default="images/aosp-api33-x86_64/cache",
                    help="work/cache directory")
    ap.add_argument("--json", help="write the distilled view JSON here")
    ap.add_argument("--html", help="write a standalone HTML explorer here")
    ap.add_argument("--no-cache", action="store_true", help="rebuild the image model")
    args = ap.parse_args(argv)

    if not args.json and not args.html:
        ap.error("nothing to do: pass --json and/or --html")

    view = build_view(args.root, args.work, args.source, use_cache=not args.no_cache)
    fw = view["framework"]["totals"]
    print(f"{args.source}: {view['totals']['findings']} findings, "
          f"{view['framework']['n_services']} framework services, "
          f"{sum(fw.values())} transactions "
          f"({fw['ungated']} exposed, {fw['gated']} gated, "
          f"{fw['needs-review']} needs-review, {fw['not-attempted']} not-attempted)",
          file=sys.stderr)

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(view, f)
        print(f"  json -> {args.json} ({os.path.getsize(args.json)} bytes)",
              file=sys.stderr)
    if args.html:
        os.makedirs(os.path.dirname(os.path.abspath(args.html)), exist_ok=True)
        html = render_html(view)
        with open(args.html, "w") as f:
            f.write(html)
        print(f"  html -> {args.html} ({len(html)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
