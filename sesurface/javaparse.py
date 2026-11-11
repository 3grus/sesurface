"""Image-independent parsing of decompiled Java (jadx output) for stage H.

This module is deliberately free of any I/O or image knowledge: it takes Java
*source text* and answers the structural questions the framework-COD pass asks of
an AIDL service. That keeps it unit-testable against small in-repo fixtures,
independent of jadx, the firmware image, or the rest of the pipeline.

The two questions, for one binder service:

  1. **Which transaction code runs which interface method?**  An AIDL-generated
     `Stub.onTransact(int code, ...)` dispatches a `switch (code)` where each
     `case N:` reads its args off the `Parcel` and calls one interface method
     (`doThing(...)`). We map `code -> methodName`. (The `TRANSACTION_<name>`
     constants are cosmetic; the switch body is the ground truth.)

  2. **Does a given method body enforce a caller check before acting?**  We scan a
     method body (and its one-hop callees in the same class) for the caller-check
     primitives a framework service uses -- `enforceCallingPermission`,
     `checkPermission`, AppOps, `getCallingUid` compared against a constant, the
     `@EnforcePermission`/`@RequiresPermission` annotations, etc.

Nothing here decides a verdict; it reports structure and evidence. The caller
(`jadx.py`) turns that into a per-transaction gated/ungated/needs-review status
with the worst-case-for-the-attacker discipline the handoff requires.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- #
# Comment / string stripping
# --------------------------------------------------------------------------- #

_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments. String literals are left intact.

    Good enough for structural scanning: a `//` or `/*` inside a string literal is
    rare in decompiled output and, if present, only ever makes us *more* cautious
    (an extra token never invents a caller check).
    """
    src = _BLOCK_COMMENT.sub(" ", src)
    src = _LINE_COMMENT.sub("", src)
    return src


# --------------------------------------------------------------------------- #
# Brace-matched block extraction
# --------------------------------------------------------------------------- #

def _matching_brace(src: str, open_idx: int) -> int:
    """Index of the `}` matching the `{` at `open_idx`, or -1.

    String and char literals are skipped so a `}` inside `"..."` does not confuse
    the depth count. Comments are assumed already stripped.
    """
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == '"' or c == "'":
            i = _skip_literal(src, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _skip_literal(src: str, i: int) -> int:
    """Return the index just past the string/char literal that starts at `i`."""
    quote = src[i]
    i += 1
    n = len(src)
    while i < n:
        if src[i] == "\\":
            i += 2
            continue
        if src[i] == quote:
            return i + 1
        i += 1
    return i


# --------------------------------------------------------------------------- #
# Classes
# --------------------------------------------------------------------------- #

@dataclass
class JavaClass:
    name: str                       # simple name (e.g. "Stub", "FooManagerService")
    extends: str = ""               # superclass as written (may be qualified)
    implements: tuple[str, ...] = ()
    body: str = ""                  # source between the outermost { }
    is_abstract: bool = False
    annotations: tuple[str, ...] = ()


_CLASS_HEADER = re.compile(
    r"(?P<mods>(?:@[\w.]+(?:\([^)]*\))?\s+|\b(?:public|private|protected|static|"
    r"final|abstract|sealed)\b\s+)*)"
    r"\bclass\s+(?P<name>\w+)"
    r"(?:\s*<[^{]*?>)?"                                   # generic params
    r"(?:\s+extends\s+(?P<ext>[\w.<>,\s]+?))?"
    r"(?:\s+implements\s+(?P<impl>[\w.<>,\s]+?))?"
    r"\s*\{",
    re.DOTALL,
)


def find_classes(src: str, _strip: bool = True) -> list[JavaClass]:
    """All class declarations in `src`, including nested ones, with their bodies."""
    if _strip:
        src = strip_comments(src)
    out: list[JavaClass] = []
    for m in _CLASS_HEADER.finditer(src):
        open_idx = m.end() - 1
        close_idx = _matching_brace(src, open_idx)
        if close_idx < 0:
            continue
        body = src[open_idx + 1:close_idx]
        mods = m.group("mods") or ""
        ext = (m.group("ext") or "").strip()
        impl = m.group("impl") or ""
        implements = tuple(x.strip() for x in impl.split(",") if x.strip())
        annots = tuple(re.findall(r"@([\w.]+)", mods))
        out.append(JavaClass(
            name=m.group("name"),
            extends=ext,
            implements=implements,
            body=body,
            is_abstract="abstract" in mods,
            annotations=annots,
        ))
    return out


# --------------------------------------------------------------------------- #
# Methods
# --------------------------------------------------------------------------- #

@dataclass
class JavaMethod:
    name: str
    body: str = ""
    annotations: tuple[str, ...] = ()
    signature: str = ""


# A method declaration: optional annotations, modifiers, return type, name, params,
# then a `{`. Constructors have no return type; we capture name either way.
_METHOD_HEADER = re.compile(
    r"(?P<annots>(?:@[\w.]+(?:\([^)]*\))?\s*)*)"
    r"(?P<mods>(?:\b(?:public|private|protected|static|final|abstract|synchronized|"
    r"native|default|strictfp)\b\s+)*)"
    r"(?:(?P<ret>[\w.$\[\]<>,\s?]+?)\s+)??"
    r"(?P<name>\w+)\s*"
    r"\((?P<params>[^;{}]*?)\)\s*"
    r"(?:throws\s+[\w.,\s]+?)?\s*\{",
    re.DOTALL,
)

_NON_METHOD_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "synchronized", "new", "return",
    "else", "do", "try", "super", "this",
})


def find_methods(class_body: str, _strip: bool = False) -> list[JavaMethod]:
    """Top-level methods declared directly in a class body.

    Only methods at brace-depth 0 of `class_body` are returned, so nested-class
    methods and in-method control blocks are not mistaken for methods. `class_body`
    is the `body` of a `JavaClass` (already comment-stripped by `find_classes`).
    """
    if _strip:
        class_body = strip_comments(class_body)
    out: list[JavaMethod] = []
    depth_spans = _top_level_spans(class_body)
    for start, end in depth_spans:
        segment = class_body[start:end]
        for m in _METHOD_HEADER.finditer(segment):
            if m.group("name") in _NON_METHOD_KEYWORDS:
                continue
            ret = (m.group("ret") or "").strip()
            # A control keyword slipping through as the "return type" is not a method.
            if ret in _NON_METHOD_KEYWORDS:
                continue
            open_idx = start + m.end() - 1
            close_idx = _matching_brace(class_body, open_idx)
            if close_idx < 0:
                continue
            annots = tuple(re.findall(r"@([\w.]+)", m.group("annots") or ""))
            out.append(JavaMethod(
                name=m.group("name"),
                body=class_body[open_idx + 1:close_idx],
                annotations=annots,
                signature=segment[m.start():open_idx].strip(),
            ))
    return out


def _top_level_spans(body: str) -> list[tuple[int, int]]:
    """Spans of `body` that sit at brace-depth 0 (outside any nested `{...}`).

    Method headers are matched only within these spans, so a method of a nested
    class (which lives inside a depth-1 block) is skipped.
    """
    spans: list[tuple[int, int]] = []
    depth = 0
    seg_start = 0
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == '"' or c == "'":
            i = _skip_literal(body, i)
            continue
        if c == "{":
            if depth == 0:
                spans.append((seg_start, i + 1))   # include the `{` for the header
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                seg_start = i + 1
        i += 1
    if seg_start < n:
        spans.append((seg_start, n))
    return spans


# --------------------------------------------------------------------------- #
# onTransact switch -> {code: interface-method}
# --------------------------------------------------------------------------- #

# Parcel / Binder boilerplate that appears in a case body but is never the
# dispatched interface method. Anything matching is ignored when we look for the
# one call that is the handler.
_PARCEL_BOILERPLATE = frozenset({
    "enforceInterface", "enforceNoDataAvail", "writeNoException", "readException",
    "writeString", "readString", "writeInt", "readInt", "writeLong", "readLong",
    "writeFloat", "readFloat", "writeDouble", "readDouble", "writeByte", "readByte",
    "writeBoolean", "readBoolean", "writeStrongBinder", "readStrongBinder",
    "writeTypedObject", "readTypedObject", "createTypedArrayList",
    "writeTypedList", "createStringArrayList", "writeStringList", "readTypedList",
    "createTypedArray", "writeTypedArray", "writeValue", "readValue",
    "writeParcelable", "readParcelable", "writeBundle", "readBundle",
    "writeMap", "readMap", "asInterface", "asBinder", "writeInterfaceToken",
    "getCallingPid", "getCallingUid", "clearCallingIdentity", "restoreCallingIdentity",
    "writeArray", "readArray", "writeException", "attachInterface",
})

_CALL = re.compile(r"(?:this\.)?(?P<name>[A-Za-z_]\w*)\s*\(")
# A `case <int>:` or `case CONST:` label.
_CASE = re.compile(r"\bcase\s+(?P<label>-?\d+|[A-Za-z_]\w*)\s*:")


def transaction_handlers(on_transact_body: str) -> dict[str, str]:
    """Map each `case` label in an onTransact switch to the interface method it calls.

    Returns `{label: methodName}` where `label` is the case label *as written* (an
    integer string like "1", or a `TRANSACTION_foo` constant name). The method name
    is the single non-boilerplate call in that case block -- the dispatched handler.

    A case with no clear handler call (e.g. the INTERFACE_TRANSACTION reply, or a
    getLength/getMaxTransactionId helper) is omitted rather than guessed.
    """
    body = on_transact_body
    out: dict[str, str] = {}
    cases = list(_CASE.finditer(body))
    for i, cm in enumerate(cases):
        start = cm.end()
        end = cases[i + 1].start() if i + 1 < len(cases) else len(body)
        block = body[start:end]
        handler = _handler_call_in_case(block)
        if handler:
            out[cm.group("label")] = handler
    return out


def _handler_call_in_case(block: str) -> Optional[str]:
    """The dispatched interface method called in one `case` block, if identifiable."""
    best: Optional[str] = None
    for m in _CALL.finditer(block):
        name = m.group("name")
        if name in _PARCEL_BOILERPLATE or name in _NON_METHOD_KEYWORDS:
            continue
        if name and name[0].islower():
            # Interface methods are lowerCamelCase; prefer the last such call
            # (args are read first, the handler is called last before the reply).
            best = name
    return best


# --------------------------------------------------------------------------- #
# Transaction constants (cosmetic names, for human-readable output)
# --------------------------------------------------------------------------- #

_TXN_CONST = re.compile(
    r"\bstatic\s+final\s+int\s+(?P<name>TRANSACTION_\w+)\s*=\s*(?P<expr>[^;]+);")
_TRAILING_INT = re.compile(r"(\d+)\s*\)?\s*$")


def transaction_constants(src: str) -> dict[str, int]:
    """Map `TRANSACTION_<name>` -> its integer code, for labelling output.

    AIDL defines `static final int TRANSACTION_doThing = (IBinder.FIRST_CALL_TRANSACTION + 0);`.
    jadx usually folds this to a literal (`= 1;`), but we also accept the unfolded
    `(... + N)` form by taking the trailing integer. Odd forms are skipped (the code
    labelling is a convenience; the method name is the real key).
    """
    out: dict[str, int] = {}
    for m in _TXN_CONST.finditer(src):
        tm = _TRAILING_INT.search(m.group("expr").strip())
        if tm:
            out[m.group("name")] = int(tm.group(1))
    return out


# --------------------------------------------------------------------------- #
# Caller-check detection
# --------------------------------------------------------------------------- #

# Each entry: (regex, short label). A hit in a method body is evidence the method
# checks *who is calling* before acting. Ordered roughly strongest-first.
_CHECK_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\benforceCallingOrSelfPermission\s*\("), "enforceCallingOrSelfPermission"),
    (re.compile(r"\benforceCallingPermission\s*\("), "enforceCallingPermission"),
    (re.compile(r"\benforcePermission\s*\("), "enforcePermission"),
    (re.compile(r"\bcheckCallingOrSelfPermission\s*\("), "checkCallingOrSelfPermission"),
    (re.compile(r"\bcheckCallingPermission\s*\("), "checkCallingPermission"),
    (re.compile(r"\bcheckPermission\s*\("), "checkPermission"),
    (re.compile(r"\benforceCallingUid\b"), "enforceCallingUid"),
    (re.compile(r"\b(?:noteOp|noteOpNoThrow|checkOp|startOp|noteProxyOp)\s*\("), "AppOps"),
    (re.compile(r"\bPermissionChecker\b"), "PermissionChecker"),
    (re.compile(r"\bPermissionManager\b"), "PermissionManager"),
    # getCallingUid() *compared against* something (a UID gate), not a bare read
    # that is only used for bookkeeping.
    (re.compile(r"getCallingUid\s*\(\s*\)\s*(?:==|!=|<|>|<=|>=)"), "uid-compare"),
    (re.compile(r"(?:==|!=|<|>|<=|>=)\s*(?:Binder\.)?getCallingUid\s*\(\s*\)"), "uid-compare"),
    (re.compile(r"\bUserHandle\.isSameApp\b"), "UserHandle.isSameApp"),
    (re.compile(r"\benforceCallingOrSelfPermission\b"), "enforceCallingOrSelfPermission"),
)

# Annotations the AIDL/framework layer uses to enforce a permission declaratively.
_ENFORCE_ANNOTS = frozenset({
    "EnforcePermission", "RequiresPermission", "RequiresNoPermission",
    "PermissionManuallyEnforced",
})

# A permission string argument, for human-readable reporting.
_PERM_STRING = re.compile(r'"(android\.permission\.[A-Z_0-9]+)"')
_PERM_CONST = re.compile(r"\b(?:Manifest\.permission|permission)\.([A-Z_0-9]+)\b")


@dataclass
class CheckEvidence:
    checks: list[str] = field(default_factory=list)      # distinct check kinds found
    permissions: list[str] = field(default_factory=list)  # permission names seen
    annotations: list[str] = field(default_factory=list)  # enforce-style annotations


def find_checks(method_src: str, annotations: tuple[str, ...] = ()) -> CheckEvidence:
    """Caller-check evidence in a single method body (+ its annotations)."""
    ev = CheckEvidence()
    seen = set()
    for pat, label in _CHECK_PATTERNS:
        if pat.search(method_src) and label not in seen:
            seen.add(label)
            ev.checks.append(label)
    for a in annotations:
        simple = a.split(".")[-1]
        if simple in _ENFORCE_ANNOTS:
            ev.annotations.append(simple)
    perms = set(_PERM_STRING.findall(method_src))
    for m in _PERM_CONST.finditer(method_src):
        name = m.group(1)
        if name not in ("permission",):
            perms.add(name)
    ev.permissions = sorted(perms)
    return ev


def callees(method_src: str) -> set[str]:
    """Bare in-class method names called in a body (for one-hop check following).

    Returns lowerCamelCase call targets that are not Parcel/Binder boilerplate --
    i.e. plausible local helper methods like `enforceFoo()` wrapping a real check.
    """
    out: set[str] = set()
    for m in _CALL.finditer(method_src):
        name = m.group("name")
        if name in _PARCEL_BOILERPLATE or name in _NON_METHOD_KEYWORDS:
            continue
        if name and name[0].islower():
            out.add(name)
    return out
