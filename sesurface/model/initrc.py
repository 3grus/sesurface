"""Parse init `.rc` service blocks -- the identity of native daemons.

A native daemon (a HAL, `cameraserver`, `installd`, ...) is not an app: its uid,
supplementary groups and retained Linux capabilities are not in any SELinux file but
in the `service` block that init uses to start it. Without this, the DAC gate has no
uid for the subject and must treat every owner/group check as "unknown". Reading the
`.rc` is what lets a HAL subject resolve to, say, uid `cameraserver` + groups
`audio camera input drmrpc` + cap `SYS_NICE`.

A service block looks like:

    service vendor.camera-provider-2-4 /vendor/bin/hw/android.hardware.camera...@2.4-service
        class hal
        user cameraserver
        group audio camera input drmrpc
        capabilities SYS_NICE
        interface android.hardware.camera.provider@2.4::ICameraProvider legacy/0
        seclabel u:r:some_domain:s0          # often ABSENT for HALs (see below)

Linking a service to its SELinux domain has two cases:
  * `seclabel u:r:DOMAIN:s0` present -> the domain is named outright.
  * no seclabel (the common HAL case) -> init labels the process by running the exec
    binary, so the domain is whatever a `type_transition init EXEC_TYPE:process`
    rule says. We resolve the exec path's file_contexts label, then look up that
    process type_transition. This is the same mechanism the kernel uses at boot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InitService:
    """One parsed `service` block (only the fields the gates need)."""
    name: str
    exec_path: str
    args: list[str] = field(default_factory=list)
    user: str = "root"              # init's default when no `user` line is given.
    groups: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    seclabel: Optional[str] = None  # the DOMAIN from `seclabel u:r:DOMAIN:s0`, if any.
    interfaces: list[str] = field(default_factory=list)  # hwservice names declared.
    classes: list[str] = field(default_factory=list)     # `class hal`, `class main`...
    source: str = ""                # "<file>:<lineno>" of the `service` line.


@dataclass
class InitRcDb:
    """Every service block found across all `.rc` files on the image."""
    services: list[InitService] = field(default_factory=list)
    files_read: list[str] = field(default_factory=list)

    def by_seclabel(self, domain: str) -> list[InitService]:
        return [s for s in self.services if s.seclabel == domain]


def parse_init_rc(files, inode_index) -> InitRcDb:
    """Parse all `.rc` files into service blocks.

    We discover the `.rc` files from the inode index (every path ending in `.rc`)
    rather than hard-coding a list, so OEM init files are covered too. The `import`
    graph does not need resolving for this purpose: a service block lives in exactly
    one file regardless of who imports it, and we read every file.
    """
    db = InitRcDb()
    rc_paths = sorted(p for p in inode_index.meta if p.endswith(".rc"))
    for path in rc_paths:
        text = files.read_text(path)
        if not text:
            continue
        db.files_read.append(path)
        _parse_one(text, path, db)
    return db


def _parse_one(text: str, path: str, db: InitRcDb) -> None:
    """Parse one .rc file, accumulating its service blocks into `db`.

    Grammar is line-oriented. A `service` line at column 0 opens a block; the option
    lines that follow (conventionally indented) belong to it until the next column-0
    stanza (`service`/`on`/`import`) or end of file. We tolerate inconsistent
    indentation by ending a block only at a new top-level stanza keyword.
    """
    cur: Optional[InitService] = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        kw = toks[0]

        # A new top-level stanza closes the current service block.
        if kw in ("service", "on", "import"):
            if cur is not None:
                db.services.append(cur)
                cur = None
            if kw == "service" and len(toks) >= 3:
                cur = InitService(name=toks[1], exec_path=toks[2], args=toks[3:],
                                  source=f"{path}:{lineno}")
            continue

        if cur is None:
            continue   # An option line outside any service block: ignore.

        # Option lines inside a service block.
        if kw == "user" and len(toks) >= 2:
            cur.user = toks[1]
        elif kw == "group" and len(toks) >= 2:
            cur.groups = toks[1:]
        elif kw == "capabilities":
            cur.capabilities = toks[1:]   # may be empty = "ambient none", still noted.
        elif kw == "class" and len(toks) >= 2:
            cur.classes.extend(toks[1:])
        elif kw == "interface" and len(toks) >= 2:
            cur.interfaces.append(" ".join(toks[1:]))
        elif kw == "seclabel" and len(toks) >= 2:
            # Format u:r:DOMAIN:s0 -> keep DOMAIN.
            bits = toks[1].split(":")
            if len(bits) >= 3:
                cur.seclabel = bits[2]
    if cur is not None:
        db.services.append(cur)


# --------------------------------------------------------------------------- #
# Domain resolution -- needs the policy, so it is a separate step from parsing.
# --------------------------------------------------------------------------- #

class DomainServiceMap:
    """Maps an SELinux domain to the init service(s) that run as it.

    Built once per policy (it consults the init `type_transition` rules). Kept apart
    from `InitRcDb` so the parsed `.rc` data stays policy-independent and cacheable.
    """

    def __init__(self, initrc: InitRcDb, policy, contexts):
        self._by_domain: dict[str, list[InitService]] = {}

        # exec_type -> domain, from every `type_transition SRC EXEC:process DOMAIN`.
        # Keyed by exec type; in practice an exec type maps to a single domain.
        exectype_to_domain: dict[str, str] = {}
        for _src, exec_type, domain in policy.process_type_transitions():
            exectype_to_domain.setdefault(exec_type, domain)

        for svc in initrc.services:
            domain = svc.seclabel
            if domain is None:
                # No explicit seclabel: resolve via the exec binary's label.
                label = contexts.label_for_path(svc.exec_path)
                if label is not None:
                    domain = exectype_to_domain.get(label[0])
            if domain:
                self._by_domain.setdefault(domain, []).append(svc)

    def services_for(self, domain: str) -> list[InitService]:
        return self._by_domain.get(domain, [])

    def items(self):
        """(domain, [services]) pairs, for callers building their own indexes."""
        return self._by_domain.items()
