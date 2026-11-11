"""Parse Android's `*_contexts` files and look labels up the way the device does.

Android does not store most SELinux labels inline; it stores *rules* that assign a
label to anything matching a path pattern, a service name, a property prefix, or an
app's identity. Those rules live in plain-text `*_contexts` files, split across
partitions. This module parses them and -- importantly -- reproduces the
**precedence** the device uses, which is subtle and easy to get wrong.

### The file_contexts precedence rule (the part people get wrong)

Each `file_contexts` file is sorted at *build* time from least-specific to
most-specific (by AOSP's `fc_sort`). At *load* time libselinux concatenates the
files in a fixed partition order, moves the entries that are exact paths (no regex
metacharacters) to the very end, and then, to label a path, takes the **last entry
in that concatenated list that matches**. Consequences:

  * an exact-path entry beats any regex, wherever it came from;
  * among regexes, a later partition (vendor, odm) beats an earlier one (plat);
  * within one file, more-specific beats less-specific (because fc_sort already
    ordered them that way and we keep file order).

This is NOT the same as "pick the globally most-specific pattern", which is what a
naive implementation does and what the Blast Radius guide's Chapter 22 flagged in
the old code. We implement the real rule below.

Note on scope: for files on the *read-only* partitions (system, vendor, ...), the
authoritative label is the `security.selinux` xattr already on the inode, which we
read directly elsewhere (`model/inode.py`). This matcher is for *runtime* paths
that do not exist in the image (under `/data`, `/dev`, parts of `/sys`), where the
label can only be predicted from these rules.
"""

from __future__ import annotations

import collections
import re
import stat
from dataclasses import dataclass, field
from typing import Optional


# The partition load order for file_contexts (and the other split context files).
# A later partition wins ties against an earlier one. Anything we do not recognise
# sorts last (after odm) -- unusual, but we would rather it win than silently lose.
PARTITION_ORDER = ["plat", "system", "system_ext", "product", "vendor", "odm"]


def _partition_rank(source_file: str) -> int:
    """Rank a context file by the partition it belongs to, from its filename.

    Filenames look like `plat_file_contexts`, `vendor_file_contexts`, etc. We map
    the prefix to its position in PARTITION_ORDER; unknown prefixes sort last.
    """
    base = source_file.rsplit("/", 1)[-1]
    for i, part in enumerate(PARTITION_ORDER):
        if base.startswith(part + "_"):
            return i
    return len(PARTITION_ORDER)


# Regex metacharacters. A pattern containing none of these is an "exact path",
# which Android moves to the end of the match list (so it beats every regex).
_META = set(".^$*+?{}[]()|\\")

# file_contexts type specifier -> the stat predicate a node must satisfy to match.
# e.g. `-c` means "character device only". A node of the wrong kind does not match
# an entry that carries a specifier, even if the path matches.
_SPEC_PRED = {
    "--": stat.S_ISREG,
    "-d": stat.S_ISDIR,
    "-l": stat.S_ISLNK,
    "-c": stat.S_ISCHR,
    "-b": stat.S_ISBLK,
    "-s": stat.S_ISSOCK,
    "-p": stat.S_ISFIFO,
}


def _label_type(context: str) -> Optional[str]:
    """Extract the type from a `user:role:type:level` context string."""
    parts = context.split(":")
    return parts[2] if len(parts) >= 3 else None


def _is_exact(pattern: str) -> bool:
    """True if the pattern is a literal path (contains no regex metacharacter)."""
    return not any(ch in _META for ch in pattern)


def _stem(pattern: str) -> str:
    """The leading literal run of a pattern, up to the first metacharacter.

    Only used to accelerate the *reverse* query (find every path of a given type)
    by first segment; it plays no part in the forward precedence rule.
    """
    out = []
    for ch in pattern:
        if ch in _META:
            break
        out.append(ch)
    return "".join(out)


def _compile(pattern: str) -> re.Pattern:
    """Compile a file_contexts pattern as a whole-path, full match.

    Android uses PCRE2; Python's `re` covers the dialect these files use in
    practice (`.`, `*`, `+`, `?`, character classes, groups, alternation,
    escapes). We anchor the end with `\\Z`; patterns are already written anchored
    at the start with a leading `/`. A pattern we cannot compile is treated as a
    literal so it still matches its exact self rather than throwing.
    """
    try:
        return re.compile(pattern + r"\Z")
    except re.error:
        return re.compile(re.escape(pattern) + r"\Z")


@dataclass
class FileContextEntry:
    """One line of a `file_contexts` file, with the facts needed to match and rank it."""
    pattern: str
    regex: re.Pattern
    spec: Optional[str]          # '-c', '-d', ... or None (matches any node kind).
    setype: str
    source_file: str             # Which context file it came from (evidence).
    exact: bool                  # Literal path? (exacts win over regexes.)
    stem: str                    # Leading literal run (reverse-query acceleration only).

    def describe(self) -> str:
        """A short evidence string naming the rule and where it lives."""
        spec = f" {self.spec}" if self.spec else ""
        return f"{self.pattern}{spec}  {self.setype}   [{self.source_file.rsplit('/',1)[-1]}]"


@dataclass
class ContextDB:
    """All parsed `*_contexts` data for one image, with device-accurate lookups.

    Load every relevant file (in any order) via the `load_*` methods, then call
    `finalize()` once to compute the file_contexts match order. After that,
    `label_for_path` answers the way the device would.
    """
    # file_contexts entries, in the order they were loaded (we sort in finalize()).
    fc: list[FileContextEntry] = field(default_factory=list)
    # The finalized match list: non-exact entries (by partition order) then exacts.
    # We scan this and take the LAST match. Built by finalize().
    _fc_ordered: list[FileContextEntry] = field(default_factory=list)
    # Reverse index: setype -> entries, for "what paths carry this label" queries.
    fc_by_type: dict[str, list[FileContextEntry]] = field(
        default_factory=lambda: collections.defaultdict(list))

    # Binder service name -> type, and the reverse. Covers service_contexts,
    # hwservice_contexts and vndservice_contexts (all the same shape).
    service_type: dict[str, str] = field(default_factory=dict)
    services_by_type: dict[str, list[str]] = field(
        default_factory=lambda: collections.defaultdict(list))

    # Property prefix/name -> type, and the reverse.
    prop_type: dict[str, str] = field(default_factory=dict)
    props_by_type: dict[str, list[str]] = field(
        default_factory=lambda: collections.defaultdict(list))

    # seapp_contexts rows, each a dict of key=value selectors+outputs, in file order.
    # The sort that decides which row wins for an app lives in `subject.py`, because
    # it depends on the app's attributes; here we just preserve the rows and order.
    seapp: list[dict[str, str]] = field(default_factory=list)

    # --- loaders ------------------------------------------------------------- #
    def load_file_contexts(self, path: str) -> None:
        for line in _lines(path):
            toks = line.split()
            if len(toks) < 2:
                continue
            pattern = toks[0]
            spec = None
            idx = 1
            if toks[1] in _SPEC_PRED:
                spec = toks[1]
                idx = 2
            if idx >= len(toks):
                continue
            setype = _label_type(toks[idx])
            if not setype:
                continue
            e = FileContextEntry(
                pattern=pattern, regex=_compile(pattern), spec=spec, setype=setype,
                source_file=path, exact=_is_exact(pattern), stem=_stem(pattern))
            self.fc.append(e)
            self.fc_by_type[setype].append(e)

    def load_service_contexts(self, path: str) -> None:
        """Parse service_contexts / hwservice_contexts / vndservice_contexts.

        All three have the same shape: `<service name>  <context>`. The three
        binder domains (binder, hwbinder, vndbinder) are distinguished by *which*
        file a name came from, which the caller tracks when it chooses files to
        load; here we just record the name->type mapping.
        """
        for line in _lines(path):
            toks = line.split()
            if len(toks) < 2:
                continue
            name, setype = toks[0], _label_type(toks[1])
            if setype:
                self.service_type[name] = setype
                self.services_by_type[setype].append(name)

    def load_property_contexts(self, path: str) -> None:
        for line in _lines(path):
            toks = line.split()
            if len(toks) < 2:
                continue
            prefix, setype = toks[0], _label_type(toks[1])
            if setype:
                self.prop_type[prefix] = setype
                self.props_by_type[setype].append(prefix)

    def load_seapp_contexts(self, path: str) -> None:
        for line in _lines(path):
            kv = dict(tok.split("=", 1) for tok in line.split() if "=" in tok)
            if kv:
                self.seapp.append(kv)

    # --- finalize + lookup --------------------------------------------------- #
    def finalize(self) -> None:
        """Compute the file_contexts match order (call once after loading).

        The order reproduces libselinux: group non-exact entries first, ordered by
        partition (plat < system_ext < ... < odm) but otherwise keeping each file's
        internal order (which build-time fc_sort already made least->most
        specific); then all exact-path entries, which thereby beat every regex.
        A stable sort preserves within-group file order.
        """
        regexes = [e for e in self.fc if not e.exact]
        exacts = [e for e in self.fc if e.exact]
        regexes.sort(key=lambda e: _partition_rank(e.source_file))  # stable
        exacts.sort(key=lambda e: _partition_rank(e.source_file))
        self._fc_ordered = regexes + exacts

    def label_for_path(self, device_path: str,
                       mode: Optional[int] = None) -> Optional[tuple[str, FileContextEntry]]:
        """Predict the SELinux type for an on-device path, device-accurately.

        `device_path` is an absolute on-device path (e.g. `/data/vendor/wifi/x`),
        not a path in the extracted tree. `mode` is the node's `st_mode` if known;
        when given, entries with a type specifier (`-c`, `-d`, ...) only match a
        node of the matching kind. Returns `(setype, entry)` where `entry` is the
        winning rule (kept as evidence), or None if nothing matches.

        We scan the finalized list and keep the LAST match -- that is exactly
        "take the last matching entry", the device's rule.
        """
        winner: Optional[FileContextEntry] = None
        for e in self._fc_ordered:
            if e.spec is not None and mode is not None:
                if not _SPEC_PRED[e.spec](mode):
                    continue
            if e.regex.match(device_path):
                winner = e
        return (winner.setype, winner) if winner else None


def _lines(path: str):
    """Yield non-blank, non-comment, stripped lines of a text file."""
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line
