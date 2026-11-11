"""Decide which policy the device actually loads, and reproduce it on the host.

There is no single "the policy" file in a Treble image. First-stage init either
uses a precompiled binary policy shipped on vendor/odm -- but only if its hashes
match the system policy it was built against -- or compiles the real policy on the
device from split CIL with `secilc`. If a tool loads the wrong policy, every result
after that is wrong. The old code took the first `precompiled_sepolicy` it found and
never checked the hashes (the Chapter 22 high-severity finding); this module does
the real decision init does.

It also records a **build identity** -- system/vendor SDK, policy version, whether
the policy was precompiled or compiled and why, enforcing status -- which every
report prints, because no finding can be interpreted without it (skew matters).
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from ..model.extract import ImageFiles


@dataclass
class BuildIdentity:
    """The facts about an image that every finding depends on."""
    system_sdk: Optional[int] = None        # ro.build.version.sdk (framework API).
    system_release: Optional[str] = None     # ro.build.version.release (e.g. "13").
    vendor_sdk: Optional[int] = None         # ro.vendor.build.version.sdk.
    board_api_level: Optional[int] = None    # ro.board.api_level (GRF freeze level).
    first_api_level: Optional[int] = None    # ro.product.first_api_level.
    policy_vers: Optional[str] = None        # plat_sepolicy_vers.txt, e.g. "33.0".
    build_type: Optional[str] = None         # ro.build.type (user => always enforcing).

    @property
    def skewed(self) -> bool:
        """True when vendor was built at an older API than system (Treble skew)."""
        return (self.system_sdk is not None and self.vendor_sdk is not None
                and self.vendor_sdk < self.system_sdk)

    @property
    def enforcing_static_guarantee(self) -> bool:
        """A `user` build is always enforcing; otherwise we cannot be sure statically."""
        return self.build_type == "user"


@dataclass
class AssembledPolicy:
    """The chosen policy file plus how and why it was chosen."""
    path: str                                # On-disk binary policy for setools to load.
    method: str                              # "precompiled" | "compiled".
    reason: str                              # Human-readable justification.
    identity: BuildIdentity
    permissive_note: str = ""
    warnings: list[str] = field(default_factory=list)


# The three (name, partition) hash pairs init compares. Each pair must either both
# exist and match, or both be absent, for the precompiled policy to be usable.
_HASH_PARTS = [("plat", "/system"), ("system_ext", "/system_ext"), ("product", "/product")]


def _prop(text: Optional[str], key: str) -> Optional[str]:
    """Pull `key=value` from a build.prop blob."""
    if not text:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return None


def read_identity(files: ImageFiles) -> BuildIdentity:
    """Read the build-identity fields from the system and vendor build.props."""
    sysp = files.read_text("/system/build.prop")
    venp = files.read_text("/vendor/build.prop")

    def as_int(v: Optional[str]) -> Optional[int]:
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    return BuildIdentity(
        system_sdk=as_int(_prop(sysp, "ro.build.version.sdk")),
        system_release=_prop(sysp, "ro.build.version.release"),
        vendor_sdk=as_int(_prop(venp, "ro.vendor.build.version.sdk")),
        board_api_level=as_int(_prop(venp, "ro.board.api_level")),
        first_api_level=as_int(_prop(venp, "ro.product.first_api_level")
                               or _prop(sysp, "ro.product.first_api_level")),
        policy_vers=(files.read_text("/vendor/etc/selinux/plat_sepolicy_vers.txt") or "").strip() or None,
        build_type=_prop(sysp, "ro.build.type"),
    )


def _precompiled_usable(files: ImageFiles) -> tuple[Optional[str], list[str]]:
    """Check the hash pairs and return (precompiled_device_path or None, reasons).

    init prefers odm's precompiled policy over vendor's, so we check odm first.
    """
    reasons: list[str] = []
    precompiled_dir = None
    for d in ("/odm/etc/selinux", "/vendor/etc/selinux"):
        if files.exists(f"{d}/precompiled_sepolicy"):
            precompiled_dir = d
            break
    if precompiled_dir is None:
        return None, ["no precompiled_sepolicy on vendor or odm -> compile"]

    for name, part in _HASH_PARTS:
        sys_sidecar = f"{part}/etc/selinux/{name}_sepolicy_and_mapping.sha256"
        pre_sidecar = f"{precompiled_dir}/precompiled_sepolicy.{name}_sepolicy_and_mapping.sha256"
        sys_hash = files.read_text(sys_sidecar)
        pre_hash = files.read_text(pre_sidecar)
        sys_has, pre_has = sys_hash is not None, pre_hash is not None
        if sys_has != pre_has:
            reasons.append(f"{name}: one sidecar present, the other absent -> compile")
            return None, reasons
        if sys_has and pre_has and sys_hash.strip() != pre_hash.strip():
            reasons.append(f"{name}: hash mismatch (system updated without vendor?) -> compile")
            return None, reasons
        if sys_has:
            reasons.append(f"{name}: hash matches")
    return f"{precompiled_dir}/precompiled_sepolicy", reasons


def assemble(files: ImageFiles, work_dir: str) -> AssembledPolicy:
    """Choose and materialise the device's policy; return it with its provenance."""
    os.makedirs(work_dir, exist_ok=True)
    identity = read_identity(files)

    pre_path, reasons = _precompiled_usable(files)
    if pre_path is not None:
        dst = os.path.join(work_dir, "sepolicy")
        files.extract_to(pre_path, dst)
        return AssembledPolicy(
            path=dst, method="precompiled",
            reason="precompiled policy hashes match system (" + "; ".join(reasons) + ")",
            identity=identity)

    # Otherwise compile the policy the way init does, from split CIL.
    return _compile(files, work_dir, identity, reasons)


# CIL inputs in secilc order (skip any that do not exist). `{V}` is the vendor
# policy version from plat_sepolicy_vers.txt.
_CIL_INPUTS = [
    "/system/etc/selinux/plat_sepolicy.cil",
    "/system/etc/selinux/mapping/{V}.cil",
    "/system/etc/selinux/mapping/{V}.compat.cil",
    "/system_ext/etc/selinux/system_ext_sepolicy.cil",
    "/system_ext/etc/selinux/mapping/{V}.cil",
    "/product/etc/selinux/product_sepolicy.cil",
    "/product/etc/selinux/mapping/{V}.cil",
    "/vendor/etc/selinux/plat_pub_versioned.cil",
    "/vendor/etc/selinux/vendor_sepolicy.cil",
    "/odm/etc/selinux/odm_sepolicy.cil",
]


def _compile(files: ImageFiles, work_dir: str, identity: BuildIdentity,
             reasons: list[str]) -> AssembledPolicy:
    """Compile the policy from split CIL with secilc, as first-stage init does.

    We mirror init's arguments: multiple-decls allowed, MLS on, no neverallow checks
    (`-N`, which init also skips -- neverallows are build-time assertions with no
    runtime effect). The target policy version comes from the loaded libsepol; we let
    secilc pick its default, which matches the device's kernel for these images.
    """
    vers = (identity.policy_vers or "").strip()
    inputs: list[str] = []
    warnings: list[str] = []
    for tmpl in _CIL_INPUTS:
        dev_path = tmpl.replace("{V}", vers)
        if "{V}" in tmpl and not vers:
            continue
        if not files.exists(dev_path):
            continue
        local = os.path.join(work_dir, dev_path.lstrip("/").replace("/", "_"))
        if files.extract_to(dev_path, local):
            inputs.append(local)

    out = os.path.join(work_dir, "sepolicy")
    cmd = ["secilc", "-m", "-M", "true", "-G", "-N", "-c", "30", *inputs,
           "-o", out, "-f", "/dev/null"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not os.path.exists(out):
        warnings.append(f"secilc failed: {proc.stderr.strip()[:300]}")
    return AssembledPolicy(
        path=out, method="compiled",
        reason="compiled split CIL with secilc (" + "; ".join(reasons) + ")",
        identity=identity, warnings=warnings)
