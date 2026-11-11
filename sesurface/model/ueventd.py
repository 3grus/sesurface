"""Parse `ueventd.rc` -- the owner/mode of device nodes that only exist at runtime.

Device nodes under `/dev` are not in the firmware image: `ueventd` (a mode of init)
creates them when the kernel announces each device, and sets their uid/gid/mode from
rules in `ueventd.rc`. So for a device-node finding (e.g. the subject can
`read/write` a `chr_file` of type `gpu_device`), the DAC gate has no inode to read --
but it *can* read the permission ueventd will give that node. That turns a DAC
verdict from "unknown (runtime path)" into a real allow/deny, which is the whole
point of this enrichment.

Rule grammar (from the header comment in AOSP's own ueventd.rc):

    /dev rules:  <devname> <mode> <uid> <gid>                e.g. /dev/null 0666 root root
    /sys rules:  <nodename> <attr> <mode> <uid> <gid>        (sysfs attribute perms)

`<devname>` may end in `*` (a prefix glob). When several rules match a node, ueventd
applies them in order and the LAST match wins, so we evaluate the same way. We keep
the /dev rules (what DAC on a device node needs) and skip the /sys attribute rules
(those gate sysfs files, which are genfscon-labelled and a separate concern).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

from .aids import AidDb


@dataclass
class UeventdRule:
    """One `/dev` permission rule: a name/glob, a mode, and owner names."""
    pattern: str            # e.g. "/dev/dri/*" or "/dev/null".
    mode: int               # octal mode, e.g. 0o666.
    uid_name: str
    gid_name: str
    source: str             # "<file>:<lineno>" for provenance.

    def matches(self, dev_path: str) -> bool:
        if self.pattern.endswith("*"):
            return dev_path.startswith(self.pattern[:-1])
        # A couple of rules use shell globs mid-string (rare); fnmatch covers both
        # the plain-equality and the glob case.
        return dev_path == self.pattern or fnmatch.fnmatch(dev_path, self.pattern)


@dataclass
class DevNodePerm:
    """The resolved DAC facts for a device node (what ueventd will set it to)."""
    path: str
    uid: Optional[int]
    gid: Optional[int]
    mode: int
    rule: UeventdRule

    def fmt(self) -> str:
        return f"{oct(self.mode)[2:]:>04} {self.uid}:{self.gid}"


@dataclass
class UeventdDb:
    """All `/dev` permission rules, kept in file+line order for last-match-wins."""
    rules: list[UeventdRule] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def resolve(self, dev_path: str, aids: AidDb) -> Optional[DevNodePerm]:
        """The permission ueventd would give `dev_path`, or None if no rule matches.

        Last matching rule wins, mirroring ueventd. uid/gid are resolved through the
        AID table; an unresolvable name yields a None number (reported, not guessed).
        """
        winner: Optional[UeventdRule] = None
        for r in self.rules:
            if r.matches(dev_path):
                winner = r
        if winner is None:
            return None
        return DevNodePerm(path=dev_path, uid=aids.uid(winner.uid_name),
                           gid=aids.gid(winner.gid_name), mode=winner.mode,
                           rule=winner)


# The on-device paths where ueventd.rc and its imports live. We read them in load
# order (system, then vendor, then odm) so later partitions' rules win, which matches
# how init processes the `import` lines at the top of the system file.
_UEVENTD_PATHS = [
    "/system/etc/ueventd.rc", "/ueventd.rc",
    "/vendor/etc/ueventd.rc", "/vendor/ueventd.rc",
    "/odm/etc/ueventd.rc", "/odm/ueventd.rc",
]


def parse_ueventd(files) -> UeventdDb:
    """Read every ueventd.rc variant and collect the `/dev` permission rules."""
    db = UeventdDb()
    for path in _UEVENTD_PATHS:
        text = files.read_text(path)
        if not text:
            continue
        got = 0
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            toks = line.split()
            # A /dev permission rule is exactly `<devname> <mode> <uid> <gid>` where
            # devname is a /dev path. Everything else (subsystem blocks, firmware_
            # directories, /sys rules with 5 tokens, imports) is not a /dev DAC rule.
            if len(toks) == 4 and toks[0].startswith("/dev"):
                try:
                    mode = int(toks[1], 8)
                except ValueError:
                    continue
                db.rules.append(UeventdRule(pattern=toks[0], mode=mode,
                                            uid_name=toks[2], gid_name=toks[3],
                                            source=f"{path}:{lineno}"))
                got += 1
        if got:
            db.sources.append(f"{path} ({got} dev rules)")
    return db


def devnodes_for_type(contexts, setype: str, limit: int = 8) -> list[str]:
    """Representative `/dev` paths a device type labels, from file_contexts.

    A device finding's backing is a file_contexts pattern like `/dev/dri/card[0-9]*`.
    To ask ueventd about it we need a concrete sample path, so we strip the regex
    metacharacters to a plain prefix (`/dev/dri/card`) -- enough to match a ueventd
    glob rule, which is itself prefix-based. Only `/dev` patterns are returned.
    """
    out: list[str] = []
    for e in contexts.fc_by_type.get(setype, []):
        pat = e.pattern
        if not pat.startswith("/dev"):
            continue
        # Cut the pattern at the first regex metacharacter to get a literal prefix.
        cut = len(pat)
        for i, ch in enumerate(pat):
            if ch in "([.*+?\\":
                cut = i
                break
        literal = pat[:cut]
        if literal and literal not in out:
            out.append(literal)
        if len(out) >= limit:
            break
    return out
