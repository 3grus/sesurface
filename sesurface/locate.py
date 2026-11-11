"""Stage G: map each reachable object to the code that handles it.

This is the bridge to the deferred ghidra/jadx attribution pass. It does NOT
decompile anything; it answers "which file would you open to see the code behind
this object, and with which tool?" so the later pass gets a precise worklist instead
of a whole firmware image to search.

The central primitive is **domain -> entrypoint binary**: a process runs in a domain
because something executed a binary whose file type has a `type_transition ... :
process <domain>` rule. Crossing those transitions with the inode index (which
binary carries that exec type) gives, for most native daemons and HALs, the exact
binary that runs as a domain. App domains and `system_server` are special-cased
(they are forked by zygote, not exec'd, so they have no exec transition).

Tool hint: ELF binaries and `.so` libraries go to **ghidra**; `.apk`/`.jar` (Java)
go to **jadx**; a device node points at the **kernel** driver behind it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .gates.dac import FILE_CLASSES
from .model.contexts import ContextDB
from .model.inode import InodeIndex
from .policy.policy import Policy
from .types import Finding


@dataclass
class CodeRef:
    """A pointer to code that handles an object, and how to open it."""
    artifact: str               # On-device path / service name / "kernel driver".
    tool: str                   # "ghidra" | "jadx" | "kernel" | "init".
    why: str = ""


@dataclass
class LocatorIndex:
    """Reusable maps the locator builds once per image."""
    # domain -> list of on-device binary paths that transition into it.
    domain_binaries: dict[str, list[str]] = field(default_factory=dict)


# The three binder context managers register themselves (no `add` rule names them),
# so they are resolved directly to their binaries rather than via a hosting domain.
_CONTEXT_MANAGERS = {
    "servicemanager": "/system/bin/servicemanager",
    "hwservicemanager": "/system/bin/hwservicemanager",
    "vndservicemanager": "/vendor/bin/vndservicemanager",
}


def _iface_base(iface: str) -> str:
    """Normalise a HIDL interface name to match init `.rc` and hwservice_contexts.

    init declares `android.hardware.camera.provider@2.4::ICameraProvider legacy/0`;
    hwservice_contexts lists `android.hardware.camera.provider::ICameraProvider`. We
    key on the version-stripped fqname (drop `@x.y` and any trailing instance), so the
    two forms line up.
    """
    import re
    first = iface.split()[0] if iface else ""      # drop the instance (e.g. "legacy/0").
    return re.sub(r"@\d+\.\d+", "", first)


def _tool_for_path(path: str) -> str:
    """Pick the decompiler a path calls for, from its extension."""
    if path.endswith((".apk", ".jar", ".dex")):
        return "jadx"
    if path.endswith(".so") or "/bin/" in path or "/lib" in path:
        return "ghidra"
    return "ghidra"


class CodeLocator:
    """Resolve objects to their handling code using the policy and inode index."""

    def __init__(self, policy: Policy, index: InodeIndex, contexts: ContextDB,
                 dsmap=None, vintf=None, appdomains=None):
        self._policy = policy
        self._index = index
        self._contexts = contexts
        self._vintf = vintf
        self._appdomains = appdomains
        self._idx = _build_domain_binaries(policy, index)
        # Interface-name -> hosting domain(s), from init `.rc` `interface` lines. This
        # resolves hwservice hosts that the policy `add` rule misses (HIDL services
        # register via hwservicemanager, so the `add` link is often on an attribute).
        self._iface_hosts: dict[str, list[str]] = {}
        if dsmap is not None:
            for domain, services in dsmap.items():
                for svc in services:
                    # Seed domain -> binary from the init service itself. A daemon
                    # started with an explicit `seclabel` in its .rc has no exec
                    # type_transition, so the policy-only map misses it, but the
                    # `service` line names the binary outright (e.g. adbd).
                    if svc.exec_path:
                        bins = self._idx.domain_binaries.setdefault(domain, [])
                        if svc.exec_path not in bins:
                            bins.append(svc.exec_path)
                    for iface in svc.interfaces:
                        base = _iface_base(iface)
                        if base:
                            self._iface_hosts.setdefault(base, [])
                            if domain not in self._iface_hosts[base]:
                                self._iface_hosts[base].append(domain)

    def member_domains(self, setype: str) -> tuple[bool, list[str]]:
        """(is_attribute, sorted concrete member domains) for a target type.

        Android policy frequently writes socket/binder rules against an attribute
        (`binderservicedomain`, `hal_drm_server`, `domain`). A concrete type reports
        `(False, [itself])`; an attribute reports `(True, [its members])`.
        """
        if self._policy.is_type(setype):
            return False, [setype]
        return True, sorted(self._policy.expand(setype))

    def locate_domain(self, domain: str) -> list[CodeRef]:
        """The binary/binaries a process in `domain` runs from."""
        refs: list[CodeRef] = []
        # Framework service domains are hosted in system_server (zygote fork), not
        # exec'd, so they have no exec transition; their code is in services.jar.
        if domain in ("system_server", "system_server_startup"):
            return [CodeRef("/system/framework/services.jar", "jadx",
                            "framework services are hosted in system_server")]
        # An attribute target (e.g. hal_omx_server) is not a concrete domain. If it
        # names exactly one concrete domain, resolve that; if several, it is an
        # aggregate with no single handler -- return empty and let the attribution
        # stage label it (expanding hundreds of members is not actionable).
        if not self._policy.is_type(domain):
            members = sorted(self._policy.expand(domain))
            if len(members) == 1:
                return self.locate_domain(members[0])
            return []
        bins = self._idx.domain_binaries.get(domain, [])
        for b in bins:
            refs.append(CodeRef(b, _tool_for_path(b),
                                f"binary transitions into domain {domain}"))
        if not refs and domain in self._policy.expand("appdomain"):
            # An app domain is zygote-forked, not exec'd, so its code is an APK. If the
            # APK ships on the image (a preinstalled/system app), name it; a plain
            # user-installed app (untrusted_app/isolated_app) has no file on a firmware
            # image, so we say so rather than invent one.
            apks = (self._appdomains.apks_for_domain(domain)
                    if self._appdomains is not None else [])
            if apks:
                for p in apks[:8]:
                    info = self._appdomains.apps.get(p)
                    pkg = f" ({info.package})" if info and info.package else ""
                    refs.append(CodeRef(p, "jadx",
                                        f"preinstalled app{pkg} runs in domain {domain} "
                                        "(seapp_contexts match)"))
            else:
                refs.append(CodeRef("(a user-installed APK)", "jadx",
                                    f"{domain} is an app domain with no APK on this "
                                    "image; its code is whatever the user installs"))
        return refs

    def locate_finding(self, finding: Finding) -> list[CodeRef]:
        """Candidate handling code for one finding, by object class."""
        setype, tclass = finding.setype, finding.tclass

        if tclass in ("binder", "unix_stream_socket", "unix_dgram_socket"):
            # The peer is a process in this domain: locate its binary. For a socket,
            # the `connectto` target type is usually the server's *domain* (the
            # listening daemon), so the same domain->binary resolution applies.
            refs = self.locate_domain(setype)
            if refs:
                return refs
            # A dedicated socket *type* with no owning domain of its own name (the
            # pdx_* channel/endpoint types are assigned by a type_transition): the
            # server is whichever domain holds the listening perms on it. We only do
            # this when the target is NOT itself a domain -- a socket finding whose
            # target IS a domain (e.g. statsd) just has an unlocated binary and must
            # stay unresolved, not be misattributed to init (which only *creates* the
            # socket under Android socket-activation and hands the fd to the daemon).
            if tclass != "binder" and setype not in self._policy.expand("domain"):
                for dom in self._socket_server_domains(setype, tclass):
                    refs.extend(self.locate_domain(dom))
            return refs

        if tclass in ("service_manager", "hwservice_manager"):
            # The binder context managers register themselves and so have no `add`
            # rule; they are a known, fixed set, resolved directly to their binaries.
            if setype in _CONTEXT_MANAGERS:
                return [CodeRef(_CONTEXT_MANAGERS[setype], "ghidra",
                                "the binder context manager process itself")]
            # Otherwise the service is hosted by whichever domain may `add` it; map
            # that domain to its binary. (The `add` rule is the cleanest host link.)
            hosts = self._service_hosts(setype, tclass)
            refs: list[CodeRef] = []
            for dom in hosts:
                refs.extend(self.locate_domain(dom))
            if refs:
                return refs
            # Fallback 1 for hwservices: match the service name to an init `interface`
            # declaration, which names the hosting daemon outright.
            for dom in self._iface_hosts_for(setype):
                refs.extend(self.locate_domain(dom))
            if refs:
                return refs
            # Fallback 2: a passthrough HAL has no process at all -- VINTF names it,
            # and the handling code is the implementing .so dlopen'd into the caller.
            refs = self._passthrough_so(setype)
            if refs:
                return refs
            return [CodeRef(f"(no provider: {setype})", "none",
                            self._unresolved_reason(setype, tclass))]

        if tclass == "property_service":
            return [CodeRef("/system/bin/init + *.rc", "init",
                            "properties are handled by init; triggers live in .rc files")]

        if tclass in FILE_CLASSES:
            refs = []
            if finding.backing:
                for art in finding.backing.artifacts[:4]:
                    if tclass == "chr_file" or tclass == "blk_file":
                        refs.append(CodeRef(art, "kernel",
                                            "device node: the handling code is the "
                                            "kernel driver behind it"))
                    elif art.endswith((".so", ".apk", ".jar")) or "/bin/" in art:
                        refs.append(CodeRef(art, _tool_for_path(art),
                                            "file is executable/loadable code"))
                    else:
                        refs.append(CodeRef(art, "ghidra",
                                            "data file: find the code that parses it "
                                            "(consumers query)"))
            return refs

        return []

    def _socket_server_domains(self, socket_type: str, tclass: str) -> list[str]:
        """Domains that listen/accept on a socket type -- its server(s).

        A client holds `connectto`; the true server holds the accept-side perms. We
        prefer `accept`/`listen` (the server's own role) and only fall back to
        `create`/`bind` if none are found, because under Android socket-activation
        `init` creates and binds a service's socket and hands the fd over -- so
        `init`/create-holders are not the server and are excluded. A rule whose
        source is a broad attribute (many domains) is a blanket allow, not identity.
        """
        def holders(perms: tuple[str, ...]) -> list[str]:
            out: list[str] = []
            for perm in perms:
                for rule in self._policy.rules_allowing(socket_type, [tclass], [perm]):
                    srcs = self._policy.expand(rule.source)
                    if len(srcs) > 8:      # a broad attribute, not a specific server
                        continue
                    for dom in sorted(srcs):
                        if dom != "init" and dom not in out:
                            out.append(dom)
            return out
        # The accept-side role identifies the server; create/bind is socket-activation.
        return holders(("accept", "listen")) or holders(("create", "bind"))

    def _service_hosts(self, service_type: str, tclass: str) -> list[str]:
        """Domains that may register (add) a service type -- its candidate hosts."""
        hosts = set()
        for rule in self._policy.rules_allowing(service_type, [tclass], ["add"]):
            # The source is the hosting domain (expand attributes to concrete types).
            for dom in self._policy.expand(rule.source):
                hosts.add(dom)
        return sorted(hosts)

    def _passthrough_so(self, hwservice_type: str) -> list[CodeRef]:
        """The implementing `.so`(s) for a passthrough HAL, via VINTF.

        We map the hwservice type's registered interface name(s) to a VINTF `<hal>`
        entry; if that entry is `passthrough`, its code is the `<package>@<ver>-impl.so`
        the caller dlopens, which we resolve against the inode index.
        """
        if self._vintf is None:
            return []
        from .model.vintf import impl_so_for
        refs: list[CodeRef] = []
        seen: set[str] = set()
        for name in self._contexts.services_by_type.get(hwservice_type, []):
            hal = self._vintf.hal_for_iface(_iface_base(name))
            if hal is None or not hal.is_passthrough:
                continue
            for so in impl_so_for(hal, self._index):
                if so in seen:
                    continue
                seen.add(so)
                refs.append(CodeRef(
                    so, "ghidra",
                    f"passthrough HAL ({hal.package}): no separate process; this .so "
                    f"is dlopen'd and run IN the caller's address space"))
        return refs

    def _unresolved_reason(self, service_type: str, tclass: str) -> str:
        """Explain why no host code was found, using what VINTF does/doesn't say.

        For an hwservice: if VINTF declares it passthrough but we found no `.so`, the
        impl is missing/named oddly; if VINTF lists it another way, a core always-on
        domain may serve it; if VINTF omits it, nothing provides it (latent HAL). For
        a plain binder service, VINTF does not apply -- no domain registers it, so the
        service type is latent on this build.
        """
        if tclass == "hwservice_manager" and self._vintf is not None:
            for name in self._contexts.services_by_type.get(service_type, []):
                hal = self._vintf.hal_for_iface(_iface_base(name))
                if hal is not None and hal.is_passthrough:
                    return ("VINTF says passthrough but no matching -impl.so was "
                            "found; check the lib*/hw naming")
                if hal is not None:
                    return (f"VINTF lists it as '{hal.transport}' but no hosting "
                            f"process resolved; may be served by an always-on core "
                            f"domain (e.g. surfaceflinger)")
            return ("not declared in any VINTF manifest: nothing provides this HAL on "
                    "this device, so the policy type is latent (deprecated/unused HAL)")
        return ("no domain registers (adds) this service on this image; the service "
                "type is latent -- not provided by this build")

    def _iface_hosts_for(self, hwservice_type: str) -> list[str]:
        """Hosting domain(s) for an hwservice type, via init `interface` declarations.

        The hwservice_contexts names registered for this type (e.g.
        `android.hardware.graphics.mapper::IMapper`) are matched against the
        version-stripped `interface` fqnames the init services declare.
        """
        out: list[str] = []
        for name in self._contexts.services_by_type.get(hwservice_type, []):
            base = _iface_base(name)
            for dom in self._iface_hosts.get(base, []):
                if dom not in out:
                    out.append(dom)
        return out


def _build_domain_binaries(policy: Policy, index: InodeIndex) -> LocatorIndex:
    """domain -> [binary paths], from process type_transitions x the inode index."""
    out: dict[str, list[str]] = {}
    for _src, exec_type, new_domain in policy.process_type_transitions():
        paths = index.paths_for_type(exec_type)
        if paths:
            out.setdefault(new_domain, [])
            for p in paths:
                if p not in out[new_domain]:
                    out[new_domain].append(p)
    return LocatorIndex(domain_binaries=out)


def attach_code(locator: CodeLocator, findings: list[Finding]) -> None:
    """Fill each finding's code pointers in place.

    `code_artifacts` is the flattened "tool: path" form (back-compat); `code_refs`
    keeps the structured `CodeRef`s so the attribution pass gets each ref's `why`
    (e.g. "passthrough HAL: dlopen'd in-caller") instead of just tool + path.
    """
    for f in findings:
        refs = locator.locate_finding(f)
        f.code_refs = refs
        f.code_artifacts = [f"{r.tool}: {r.artifact}" for r in refs]
