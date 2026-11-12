"""Orchestration: build the image model once, then run per-subject analyses.

This ties the stages together and enforces the caching split the plan calls for:
the *source-independent* work -- carving partitions, reading every inode, parsing
the context files, assembling the policy -- is done once per image and cached to
disk. Running a second source domain reloads that cache and only redoes the cheap
per-subject stages (subject resolution + the gate engine). That is what makes
`reach -s a,b,c` or repeated invocations fast.

The SELinux policy object itself is not cached (it wraps a C library handle); it is
cheaply reloaded from the assembled binary policy file, whose path the cache holds.
"""

from __future__ import annotations

import os
import pickle
from dataclasses import dataclass

from .backing import BackingResolver
from .gates.combine import build_findings
from .gates.te import TEReach, compute_te_reach
from .locate import CodeLocator, attach_code
from .model.aids import AidDb, load_aids
from .model.contexts import ContextDB
from .model.contextload import load_contexts
from .model.extract import ImageFiles
from .model.initrc import DomainServiceMap, InitRcDb, parse_init_rc
from .model.appdomain import AppDomainIndex, build_app_domain_index
from .model.kerneldrv import KernelArtifacts, build_kernel_artifacts
from .model.inode import InodeIndex, build_inode_index
from .model.partitions import PartitionSet, build_partition_set
from .model.ueventd import UeventdDb, parse_ueventd
from .model.vintf import VintfDb, parse_vintf
from .pivot import PivotReport, compute_pivots
from .policy.assemble import AssembledPolicy, assemble
from .policy.policy import Policy
from .subject import resolve_subject
from .types import Finding, Subject

_CACHE_VERSION = 7   # Bump when the cached structures change shape.


@dataclass
class ImageModel:
    """Everything about an image that does not depend on the source domain."""
    image_dir: str
    work_dir: str
    fingerprint: str
    partitions: PartitionSet
    inodes: InodeIndex
    contexts: ContextDB
    assembled: AssembledPolicy
    # Enrichment from init/ueventd (native-daemon identity + device-node DAC). These
    # are policy-independent, so they live in the cached model like the rest.
    initrc: InitRcDb
    ueventd: UeventdDb
    aids: AidDb
    vintf: VintfDb
    appdomains: "AppDomainIndex"
    kernel: "KernelArtifacts"

    def open_policy(self) -> Policy:
        """Load the assembled policy with setools (cheap; not cached)."""
        return Policy(self.assembled.path)


@dataclass
class ReachReport:
    """The result of analysing one subject against one image."""
    model: ImageModel
    subject: Subject
    te: TEReach
    findings: list[Finding]
    pivots: PivotReport


def _fingerprint(image_dir: str) -> str:
    """A cheap identity for an image dir: each .img file's name, size and mtime.

    Carving and reading are deterministic in these inputs, so if none changed the
    cached model is still valid.
    """
    parts = []
    for name in sorted(os.listdir(image_dir)):
        if name.endswith(".img"):
            st = os.stat(os.path.join(image_dir, name))
            parts.append(f"{name}:{st.st_size}:{int(st.st_mtime)}")
    return f"v{_CACHE_VERSION}|" + "|".join(parts)


def build_image_model(image_dir: str, work_dir: str,
                      use_cache: bool = True, read_labels: bool = True) -> ImageModel:
    """Build (or load from cache) the source-independent model of an image."""
    os.makedirs(work_dir, exist_ok=True)
    cache_path = os.path.join(work_dir, "model.pkl")
    fp = _fingerprint(image_dir)

    if use_cache and os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                cached: ImageModel = pickle.load(f)
            if cached.fingerprint == fp and os.path.exists(cached.assembled.path):
                return cached
        except Exception:
            pass   # Corrupt or stale cache: rebuild.

    parts = build_partition_set(image_dir, os.path.join(work_dir, "parts"))
    files = ImageFiles(parts)
    try:
        inodes = build_inode_index(parts, read_labels=read_labels)
        # Mount APEX payloads (/apex/<pkg>/bin/*, /apex/<pkg>/javalib/*.jar) and index
        # the boot ramdisk, so native daemons and APEX javalib services resolve. This
        # adds partitions to `parts`; `files` is re-created below so its resolver sees
        # the new /apex/* mounts.
        from .model.apex import index_apex_partitions
        from .model.ramdisk import index_ramdisk
        parts.notes.extend(
            index_apex_partitions(parts, files, inodes, work_dir,
                                  read_labels=read_labels))
        parts.notes.extend(index_ramdisk(image_dir, inodes))
        files.close()
        files = ImageFiles(parts)
        contexts = load_contexts(files, os.path.join(work_dir, "ctx"))
        assembled = assemble(files, work_dir)
        # init/ueventd enrichment: native-daemon identity + device-node DAC facts.
        aids = load_aids(files)
        initrc = parse_init_rc(files, inodes)
        ueventd = parse_ueventd(files)
        vintf = parse_vintf(files, inodes)
        # Map each preinstalled APK to its app domain (seapp_contexts), so the locator
        # can name the concrete APK behind an app-domain target (blast-radius pivots).
        appdomains = build_app_domain_index(files, inodes, contexts)
    finally:
        files.close()

    # Kernel image + loadable modules, so a device-ioctl pivot can name where the
    # driver code lives (built into the kernel binary, or a specific .ko).
    kernel = build_kernel_artifacts(image_dir, inodes)

    model = ImageModel(image_dir=image_dir, work_dir=work_dir, fingerprint=fp,
                       partitions=parts, inodes=inodes, contexts=contexts,
                       assembled=assembled, initrc=initrc, ueventd=ueventd,
                       aids=aids, vintf=vintf, appdomains=appdomains, kernel=kernel)
    if use_cache:
        with open(cache_path, "wb") as f:
            pickle.dump(model, f)
    return model


def run_reach(model: ImageModel, policy: Policy, domain: str,
              follow_transitions: bool = True) -> ReachReport:
    """Analyse one source domain against an already-built image model."""
    # Resolve native-daemon identity (uid/gids/caps) from init `.rc`, when the domain
    # is one init starts. Needs the policy (to map exec -> domain), so it is built
    # here rather than cached with the image.
    dsmap = DomainServiceMap(model.initrc, policy, model.contexts)
    subject = resolve_subject(policy, model.contexts, domain,
                              dsmap=dsmap, aids=model.aids)
    backing = BackingResolver(policy, model.inodes, model.contexts)
    te = compute_te_reach(policy, domain, follow_transitions=follow_transitions)
    findings = build_findings(policy, subject, model.inodes, backing, te,
                              ueventd=model.ueventd, aids=model.aids)

    # Stage G: attach handling-code pointers to each finding (for the deferred
    # ghidra/jadx pass). Stage F: compute pivot edges from the findings.
    locator = CodeLocator(policy, model.inodes, model.contexts, dsmap=dsmap,
                          vintf=model.vintf, appdomains=model.appdomains)
    attach_code(locator, findings)
    pivots = compute_pivots(policy, subject, findings, te.pivots)

    # Enrich each BECOMES target with the binary that runs as that domain (the thing
    # to open in ghidra/jadx to understand what the subject would become).
    for p in pivots.becomes:
        if not p.code:
            refs = locator.locate_domain(p.to_domain)
            p.code = [f"{r.tool}: {r.artifact}" for r in refs]

    return ReachReport(model=model, subject=subject, te=te, findings=findings,
                       pivots=pivots)
