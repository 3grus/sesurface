"""Stage E: back each reachable (type, class) with the real object(s) it names.

A reachable type from the TE gate is only a *potential* object. This stage answers
"what concrete thing carries this label on this device?", and classifies the answer
into a tier (guide ch. 1):

  * confirmed   -- an artifact exists in the image: an inode with this label, a
                   service_contexts entry, a property_contexts entry.
  * predicted   -- nothing in the image, but readable config creates it at runtime:
                   a file_contexts pattern for a /data or /dev path, a genfscon entry
                   for a /proc or /sys path.
  * policy-only -- the rule exists but nothing backs it. A latent risk worth noting,
                   not a present object.

Resolution is per object class, because each class is backed differently: files by
inodes/file_contexts/genfscon, binder services by service_contexts, properties by
property_contexts, and a binder *domain* (the target of a `binder call`) by the
process itself (the locator stage later maps it to the hosting binary).
"""

from __future__ import annotations

from .gates.dac import FILE_CLASSES
from .model.contexts import ContextDB
from .model.inode import InodeIndex
from .policy.policy import Policy
from .types import Backing, BackingTier


class BackingResolver:
    """Resolve types to objects using the image indexes and the policy."""

    def __init__(self, policy: Policy, index: InodeIndex, contexts: ContextDB):
        self._index = index
        self._contexts = contexts
        # Reverse genfscon index: type -> [(fs, path)], for /proc, /sys, ... labels
        # that live in the policy, not in any file_contexts file.
        self._genfs: dict[str, list[tuple[str, str]]] = {}
        for gl in policy.genfs_labels():
            self._genfs.setdefault(gl.setype, []).append((gl.fs, gl.path))

    def resolve(self, setype: str, tclass: str, limit: int = 20) -> Backing:
        if tclass in FILE_CLASSES:
            return self._resolve_file(setype, tclass, limit)
        if tclass in ("service_manager",):
            return self._resolve_service(setype, tclass, limit)
        if tclass in ("hwservice_manager",):
            return self._resolve_service(setype, tclass, limit)
        if tclass == "property_service":
            return self._resolve_property(setype, tclass, limit)
        if tclass == "binder":
            # The target of a binder call is a server *process domain*; the concrete
            # object is that running process. The locator stage maps the domain to
            # the binary that runs as it; here we record the domain itself.
            return Backing(setype=setype, tclass=tclass, tier=BackingTier.PREDICTED,
                           kind="process-domain", artifacts=[setype],
                           note="binder peer is the process running in this domain; "
                                "see the locator for the hosting binary")
        # Other classes (fd, process, capability, sockets without a file, ...) have
        # no standalone backing object; they qualify another finding.
        return Backing(setype=setype, tclass=tclass, tier=BackingTier.POLICY_ONLY,
                       kind="n/a", artifacts=[],
                       note="no standalone object for this class")

    def _resolve_file(self, setype: str, tclass: str, limit: int) -> Backing:
        # 1. Authoritative: inodes in the image carrying this label (confirmed).
        paths = self._index.paths_for_type(setype, limit=limit)
        if paths:
            return Backing(setype=setype, tclass=tclass, tier=BackingTier.CONFIRMED,
                           kind="file", artifacts=paths,
                           note=f"{len(self._index.by_type.get(setype, []))} inode(s) "
                                f"carry this label")
        # 2. Kernel pseudo-fs label from the policy (predicted /proc, /sys, ...).
        if setype in self._genfs:
            arts = [f"{fs}:{path}" for fs, path in self._genfs[setype][:limit]]
            return Backing(setype=setype, tclass=tclass, tier=BackingTier.PREDICTED,
                           kind="genfs", artifacts=arts,
                           note="labelled by genfscon on a kernel filesystem; the "
                                "path exists at runtime, not in the image")
        # 3. A file_contexts pattern for a runtime path (predicted /data, /dev, ...).
        entries = self._contexts.fc_by_type.get(setype, [])
        if entries:
            arts = [e.pattern for e in entries[:limit]]
            return Backing(setype=setype, tclass=tclass, tier=BackingTier.PREDICTED,
                           kind="runtime-path", artifacts=arts,
                           note="no inode in the image; file_contexts predicts this "
                                "path is created at runtime (/data, /dev, ...)")
        # 4. Nothing backs it.
        return Backing(setype=setype, tclass=tclass, tier=BackingTier.POLICY_ONLY,
                       kind="file", artifacts=[],
                       note="no inode, genfscon or file_contexts entry labels this "
                            "type; the allow rule is latent on this device")

    def _resolve_service(self, setype: str, tclass: str, limit: int) -> Backing:
        names = self._contexts.services_by_type.get(setype, [])
        if names:
            return Backing(setype=setype, tclass=tclass, tier=BackingTier.CONFIRMED,
                           kind="service", artifacts=names[:limit],
                           note="service name(s) from *_service_contexts")
        return Backing(setype=setype, tclass=tclass, tier=BackingTier.POLICY_ONLY,
                       kind="service", artifacts=[],
                       note="no service_contexts entry maps a name to this type")

    def _resolve_property(self, setype: str, tclass: str, limit: int) -> Backing:
        prefixes = self._contexts.props_by_type.get(setype, [])
        if prefixes:
            return Backing(setype=setype, tclass=tclass, tier=BackingTier.CONFIRMED,
                           kind="property", artifacts=prefixes[:limit],
                           note="property name/prefix(es) from *_property_contexts")
        return Backing(setype=setype, tclass=tclass, tier=BackingTier.POLICY_ONLY,
                       kind="property", artifacts=[],
                       note="no property_contexts entry maps a property to this type")
