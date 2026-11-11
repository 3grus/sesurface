"""The one module that touches `setools`.

Everything version-sensitive about the setools 4.x API is contained here. The rest
of sesurface only ever sees the plain, frozen value objects defined below -- never a
raw setools object -- so a setools upgrade can only ever break this file.

Why the setools *library* rather than shelling out to `sesearch`/`seinfo`:

  * the transitive engines (domain-transition and information-flow analysis) are
    only available through the API;
  * the policy is parsed once and queried in memory, instead of re-parsed on every
    CLI invocation;
  * results come back as typed objects.

We still emit an equivalent `sesearch` string for every rule-based finding (see
`AllowRule.sesearch`), so any result can be re-checked by hand with the CLI -- which
is the cross-check the Blast Radius guide recommends.

Validated against setools 4.4.4 (Ubuntu 24.04) on a real Android 13 policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

try:
    import setools
    from setools import (
        SELinuxPolicy,
        TERuleQuery,
        DomainTransitionAnalysis,
        InfoFlowAnalysis,
        PermissionMap,
    )
    _IMPORT_ERROR: Optional[Exception] = None
except Exception as e:  # pragma: no cover - environment dependent
    setools = None  # type: ignore
    _IMPORT_ERROR = e


def require_setools() -> None:
    """Raise a helpful error if setools is not importable.

    setools is not pip-installable; it comes from the distro (`python3-setools`) and
    must be visible to the venv (`uv venv --system-site-packages`). `sesurface doctor`
    checks this.
    """
    if setools is None:
        raise RuntimeError(
            f"The 'setools' package is not importable: {_IMPORT_ERROR!r}\n"
            "Install it from the distro (Ubuntu: `apt install python3-setools`) and "
            "create the venv with `uv venv --system-site-packages`. Run `sesurface doctor`."
        )


# --------------------------------------------------------------------------- #
# Value objects. The rest of sesurface sees only these.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class AllowRule:
    """One `allow` (or `allowxperm`) rule, flattened to strings.

    `perms` is the permission set for a plain allow. For an `allowxperm` rule,
    `xperm` holds the operation and its command set, e.g. "ioctl 0x6400-0x64ff";
    those are the specific driver ioctl numbers the subject may issue -- the kernel
    attack surface for a device node.
    """
    source: str
    target: str
    tclass: str
    perms: frozenset[str]
    cond: Optional[str] = None      # Conditional (boolean) expression, if any.
    xperm: Optional[str] = None     # "<op> <ranges>" for an allowxperm rule.

    def sesearch(self) -> str:
        """A `sesearch` command that isolates this rule, for manual verification."""
        flag = "-AX" if self.xperm else "-A"
        return (f"sesearch {flag} -s {self.source} -t {self.target} "
                f"-c {self.tclass} <sepolicy>")


@dataclass(frozen=True)
class DomainTransition:
    """A process domain transition edge: `source` can become `target`.

    `entrypoints` lists the executable types that trigger the transition (the
    binary a process in `source` must execve to land in `target`). Each is
    `(exec_type, (permission rule texts...))`. An exec transition is a BECOMES
    pivot: running that binary gives the subject the target domain.
    """
    source: str
    target: str
    entrypoints: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True)
class GenfsLabel:
    """A label the policy assigns to a path on a kernel pseudo-filesystem.

    genfscon statements live inside the policy (not in any text file on the image),
    which is why a tool that looks for a `genfs_contexts` file finds nothing and
    loses every /proc and /sys label. We read them from the loaded policy instead.
    """
    fs: str                 # Filesystem type, e.g. "proc", "sysfs", "debugfs".
    path: str               # Path prefix the label applies to.
    setype: str             # SELinux type.


@dataclass(frozen=True)
class FsUse:
    """How a whole filesystem type gets its labels (`fs_use_*`).

    - xattr: labels come from on-disk xattrs (ext4, erofs, f2fs).
    - task : the creating process's label (pipefs, sockfs).
    - trans: a type_transition decides (tmpfs, devpts).
    """
    behavior: str           # "xattr" | "task" | "trans".
    fs: str
    setype: str


@dataclass(frozen=True)
class MlsConstraintInfo:
    """A single `mlsconstrain` statement, kept for the MLS gate.

    Evaluating arbitrary MLS constraint expressions symbolically is hard, so we keep
    the raw infix expression plus two booleans the common Android constraints turn
    on (whether the rule exempts `mlstrustedsubject` / `mlstrustedobject`). The MLS
    gate (`gates/mls.py`) uses these to apply the standard Android model and falls
    back to "unknown" for anything exotic, rather than guessing. See guide ch. 11.
    """
    tclass: str
    perms: frozenset[str]
    infix: str                      # Human-readable expression, e.g. "l1 dom l2 or ...".
    mentions_trusted_subject: bool
    mentions_trusted_object: bool


# --------------------------------------------------------------------------- #
# The policy wrapper
# --------------------------------------------------------------------------- #

class Policy:
    """A loaded SELinux policy, exposing exactly the queries sesurface needs."""

    def __init__(self, path: str):
        require_setools()
        self.path = path
        self._p = SELinuxPolicy(path)
        self._permmap = None
        self._permissive: Optional[frozenset[str]] = None
        self._expand_cache: dict[str, frozenset[str]] = {}

    # -- identity ------------------------------------------------------------- #
    @property
    def policy_version(self) -> int:
        """The binary policy version number (e.g. 30), not the Android release."""
        return int(self._p.version)

    @property
    def toolchain(self) -> str:
        return f"setools {getattr(setools, '__version__', '?')}"

    def types(self) -> list[str]:
        return sorted(str(t) for t in self._p.types())

    def classes(self) -> list[str]:
        return sorted(str(c) for c in self._p.classes())

    def is_type(self, name: str) -> bool:
        try:
            self._p.lookup_type(name)
            return True
        except Exception:
            return False

    def expand(self, name: str) -> frozenset[str]:
        """Expand a type-or-attribute name to the set of concrete types it covers.

        Android policy is written mostly against attributes (`appdomain`,
        `domain`, `file_type`, ...). `expand("appdomain")` returns every app
        domain. A concrete type expands to just itself. Memoised, because the
        reverse/consumers queries expand the same attributes many times.
        """
        cached = self._expand_cache.get(name)
        if cached is not None:
            return cached
        result = self._expand_uncached(name)
        self._expand_cache[name] = result
        return result

    def _expand_uncached(self, name: str) -> frozenset[str]:
        try:
            t = self._p.lookup_type_or_attr(name)
        except Exception:
            try:
                t = self._p.lookup_type(name)
            except Exception:
                return frozenset()
        return frozenset(str(x) for x in t.expand())

    def attributes_of(self, name: str) -> frozenset[str]:
        """The attributes a concrete type belongs to (e.g. untrusted_app -> appdomain).

        Used to exclude a subject's own rules when running the reverse "consumers"
        query -- a rule written against an attribute the subject holds is the subject
        reading its own data, not a pivot into another domain.
        """
        try:
            t = self._p.lookup_type(name)
            attrs = t.attributes
            # `attributes` may be a method (returns an iterator) or an iterable.
            if callable(attrs):
                attrs = attrs()
            return frozenset(str(a) for a in attrs)
        except Exception:
            return frozenset()

    def permissive_domains(self) -> frozenset[str]:
        """Domains that are permissive: for them the SELinux (TE) gate is OPEN.

        Denials are logged but not enforced, so a permissive domain can do anything
        TE would otherwise block. CTS forbids these on user builds, but we are
        auditing exactly the images that may not comply (and emulator/userdebug
        builds have some, e.g. `su`).
        """
        if self._permissive is None:
            self._permissive = frozenset(
                str(t) for t in self._p.types() if t.ispermissive)
        return self._permissive

    # -- direct allow / allowxperm rules sourced at a domain ------------------ #
    def allow_rules_from(self, domain: str) -> Iterator[AllowRule]:
        """Every allow and allowxperm rule whose (expanded) source is `domain`.

        `source_indirect=True` is essential: it makes a concrete domain also match
        rules written against the attributes it holds. Without it you miss almost
        everything on Android, because the rules target attributes, not the domain
        name. This is the L0 "direct" reachability layer.
        """
        for ruletype in ("allow", "allowxperm"):
            q = TERuleQuery(self._p, source=domain, source_indirect=True,
                            ruletype=[ruletype])
            for r in q.results():
                yield _to_allow(r)

    def rules_allowing(self, target_type: str, tclass: Iterable[str],
                       perms: Iterable[str]) -> Iterator[AllowRule]:
        """Reverse query: which domains may do `perms` to `target_type`:`tclass`.

        This is the "consumers" query the pivot stage needs -- e.g. "who can read,
        execute or map a type my subject can write?" Each such domain is a candidate
        ATTACKS (or BECOMES) edge. `target_indirect=True` expands attributes on the
        target side too.
        """
        q = TERuleQuery(self._p, target=target_type, target_indirect=True,
                        tclass=list(tclass), perms=set(perms), ruletype=["allow"])
        for r in q.results():
            yield _to_allow(r)

    # -- process transition graph --------------------------------------------- #
    def transitions_from(self, domain: str) -> Iterator[DomainTransition]:
        """Domain-transition edges out of `domain` (who it can become by exec)."""
        dta = DomainTransitionAnalysis(self._p, reverse=False)
        for step in dta.transitions(domain):
            eps = []
            for ep in getattr(step, "entrypoints", []) or []:
                eps.append((str(ep.name),
                            tuple(str(x) for x in getattr(ep, "entrypoint", []))))
            yield DomainTransition(source=str(step.source), target=str(step.target),
                                   entrypoints=tuple(eps))

    def process_type_transitions(self) -> Iterator[tuple[str, str, str]]:
        """Every `type_transition SRC EXEC:process NEW` as (src, exec_type, new).

        This maps an executable's type to the domain a process lands in when init
        (or anything) runs it -- the static link from a binary to the domain it
        runs as.
        """
        q = TERuleQuery(self._p, ruletype=["type_transition"], tclass=["process"])
        for r in q.results():
            yield (str(r.source), str(r.target), str(r.default))

    def file_type_transitions_from(self, domain: str) -> Iterator[tuple[str, str, str]]:
        """`type_transition` rules for files/dirs sourced at `domain`.

        Yields (parent_dir_type, newfile_type, optional_name). Used to predict the
        label a file gets when `domain` creates it under /data (guide ch. 13).
        """
        q = TERuleQuery(self._p, source=domain, source_indirect=True,
                        ruletype=["type_transition"])
        for r in q.results():
            if str(r.tclass) == "process":
                continue
            name = getattr(r, "filename", None)
            yield (str(r.target), str(r.default), str(name) if name else "")

    # -- information-flow closure (the noisy, maximal layer) ------------------ #
    def infoflow_targets(self, source: str, min_weight: int = 3,
                         exclude: Optional[Iterable[str]] = None) -> Iterator[tuple[str, list[str]]]:
        """Types reachable by OUTBOUND information flow from `source`, transitively.

        This is the maximal "IPC closure" layer, and the noisiest. It uses a
        permission map that weights each permission as read-like / write-like.

        Caveat (documented limitation): setools' default permission map has no
        entries for Android's `service_manager`, `hwservice_manager` or
        `property_service` classes, and treats `binder call` as one-directional.
        So binder/property flows are under-counted here; sesurface does not rely on
        this layer for those -- they are covered by the direct layer and the
        reverse `rules_allowing` query. A higher `min_weight` keeps the noise down.
        """
        if self._permmap is None:
            self._permmap = PermissionMap()
        ifa = InfoFlowAnalysis(self._p, self._permmap, min_weight=min_weight)
        if exclude:
            try:
                ifa.exclude = list(exclude)
            except Exception:
                pass
        for step in ifa.infoflows(source, out=True):
            tgt = getattr(step, "target", None)
            if tgt is None:
                continue
            rules = [str(r) for r in getattr(step, "rules", [])]
            yield (str(tgt), rules)

    # -- kernel-fs labels and fs_use ------------------------------------------ #
    def genfs_labels(self) -> Iterator[GenfsLabel]:
        """All genfscon labels (the /proc, /sys, debugfs, ... labels)."""
        for g in self._p.genfscons():
            setype = _ctx_type(g.context)
            if setype:
                yield GenfsLabel(fs=str(g.fs), path=str(g.path), setype=setype)

    def fs_uses(self) -> Iterator[FsUse]:
        """How each filesystem type is labelled (xattr / task / trans)."""
        for u in self._p.fs_uses():
            setype = _ctx_type(u.context)
            if setype:
                # ruletype is an enum like FSUseRuletype.fs_use_xattr.
                beh = str(u.ruletype).split("_")[-1]
                yield FsUse(behavior=beh, fs=str(u.fs), setype=setype)

    # -- MLS constraints ------------------------------------------------------ #
    def mls_constraints(self) -> Iterator[MlsConstraintInfo]:
        """Every `mlsconstrain` statement in the policy (for the MLS gate)."""
        for c in self._p.constraints():
            if str(c.ruletype) != "mlsconstrain":
                continue
            infix = _render_infix(c)
            yield MlsConstraintInfo(
                tclass=str(c.tclass),
                perms=frozenset(str(p) for p in c.perms),
                infix=infix,
                mentions_trusted_subject="mlstrustedsubject" in infix,
                mentions_trusted_object="mlstrustedobject" in infix,
            )


# --------------------------------------------------------------------------- #
# Helpers that unpack raw setools objects (kept at module scope, out of the API).
# --------------------------------------------------------------------------- #

def _to_allow(r) -> AllowRule:
    """Flatten a setools rule object to our `AllowRule`."""
    cond = None
    try:
        if getattr(r, "conditional", None) is not None:
            cond = str(r.conditional)
    except Exception:
        pass
    xperm = None
    perms: frozenset[str]
    xt = getattr(r, "xperm_type", None)
    if xt:
        # allowxperm: perms is a set of ioctl command numbers; summarise as ranges.
        xperm = f"{xt} {_ranges(r.perms)}"
        perms = frozenset()
    else:
        perms = frozenset(str(p) for p in getattr(r, "perms", []) or [])
    return AllowRule(
        source=str(r.source), target=str(r.target), tclass=str(r.tclass),
        perms=perms, cond=cond, xperm=xperm)


def _ranges(perms) -> str:
    """Summarise a set of integers as compact hex ranges, e.g. '0x10-0x12 0x40'."""
    nums = sorted(int(x) for x in perms)
    if not nums:
        return ""
    out, start, prev = [], nums[0], nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        out.append(f"{start:#x}" if start == prev else f"{start:#x}-{prev:#x}")
        start = prev = n
    out.append(f"{start:#x}" if start == prev else f"{start:#x}-{prev:#x}")
    return " ".join(out)


def _render_infix(constraint) -> str:
    """Render a constraint's infix expression as readable text.

    setools' `expression.infix()` yields a stream of tokens where the operands that
    name a *set* of types/roles/users come through as Python sets of policy objects
    (whose default repr is noisy, e.g. `frozenset({<TypeAttribute(...)>})`). We
    flatten those to space-joined names inside braces, and pass operators through.
    """
    try:
        tokens = list(constraint.expression.infix())
    except Exception:
        return str(getattr(constraint, "expression", ""))
    out: list[str] = []
    for tok in tokens:
        if isinstance(tok, (set, frozenset)):
            names = sorted(str(x) for x in tok)
            out.append("{" + " ".join(names) + "}")
        else:
            out.append(str(tok))
    return " ".join(out)


def _ctx_type(context) -> Optional[str]:
    """Extract the type field from a setools Context (robust across versions)."""
    try:
        return str(context.type_)
    except Exception:
        parts = str(context).split(":")
        return parts[2] if len(parts) >= 3 else None
