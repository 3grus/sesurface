"""`sesurface doctor` -- environment self-check.

sesurface leans on a handful of external programs and Python bindings that are not
pip-installable (they come from the distro: setools, libselinux, secilc, the
filesystem extractors). If one is missing, the honest thing to do is say so and
say *which part of the analysis stops working* -- never to silently fall back to a
wrong answer. That is what this module is for.

It is deliberately dependency-free (stdlib only) so it runs even when nothing else
is installed, which is exactly the situation where you most want to run it.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from dataclasses import dataclass, field


@dataclass
class Probe:
    """One thing we check for, and what it buys us.

    `kind` is "binding" (an importable Python module) or "tool" (an executable on
    PATH). `enables` is a plain-English statement of what works when it is present,
    and `degrades` is what we lose without it -- printed so the user understands the
    blast radius of a missing dependency, so to speak.

    `env`/`paths` let a tool that is not on PATH still be found: the attribution tools
    (jadx, ghidra) are typically unpacked under $HOME, not apt-installed, so we also
    honour an env var and a short list of well-known install locations.
    """
    name: str
    kind: str            # "binding" | "tool"
    enables: str
    degrades: str
    apt: str             # Ubuntu package that provides it (for the hint line).
    required: bool       # If True, core analysis cannot run at all without it.
    env: str = ""        # Env var that may point straight at the executable.
    paths: list[str] = field(default_factory=list)  # Candidate absolute locations.


# The full dependency surface, grouped by the pipeline stage each one serves.
# Keeping the list here (rather than scattered through the code) means `doctor`
# and the real stages agree on exactly one source of truth.
PROBES: list[Probe] = [
    # --- Policy stage (B): the heart. Without setools there is no analysis. -----
    Probe("setools", "binding",
          "Parse and query the SELinux policy (allow rules, transitions, infoflow).",
          "No policy analysis at all -- this is the core engine.",
          "python3-setools", required=True),
    Probe("secilc", "tool",
          "Compile the device's split CIL policy when no precompiled binary applies.",
          "Cannot assemble policy for skewed images (e.g. Android 11 vendor under a "
          "newer system); limited to a matching precompiled_sepolicy if present.",
          "secilc", required=False),
    # --- Image model stage (A): labels and DAC read from the real image. -------
    Probe("selinux", "binding",
          "Resolve runtime-path labels via libselinux selabel (for /data, /dev).",
          "Runtime-path labels fall back to our own file_contexts matcher, which "
          "approximates (not reproduces) Android's libselabel.",
          "python3-selinux", required=False),
    Probe("debugfs", "tool",
          "Read true uid/gid/mode/xattr from ext4 images without mounting.",
          "The DAC gate loses ground truth on ext4 partitions.",
          "e2fsprogs", required=False),
    Probe("dump.erofs", "tool",
          "Read true uid/gid/mode/xattr from EROFS images (common on Android 13+).",
          "The DAC gate loses ground truth on EROFS partitions.",
          "erofs-utils", required=False),
    Probe("getfattr", "tool",
          "Read SELinux xattrs from a read-only loop-mount of an image.",
          "One of the two ways to get authoritative file labels; debugfs/dump.erofs "
          "cover the no-mount path.",
          "attr", required=False),
    # --- Unpacking helpers: only needed if the image is not already extracted. --
    Probe("simg2img", "tool",
          "Convert Android sparse images to raw before extraction.",
          "Cannot handle sparse .img inputs; pre-extracted trees still work.",
          "android-sdk-libsparse-utils", required=False),
    Probe("lpunpack", "tool",
          "Split super.img into its dynamic partitions.",
          "Cannot unpack super.img; already-split partition trees still work.",
          "not packaged on noble -- build from AOSP system/extras (only needed for super.img)",
          required=False),
    # --- App stage: APK parsing (this one IS pip-installable, so it is a dep). --
    Probe("androguard", "binding",
          "Parse APK manifests, signing certs and DEX for app->domain resolution.",
          "No app-subject resolution or exported-component surface.",
          "(pip) androguard", required=False),
    # --- Attribution stage (H): decompile handlers to resolve the in-code gate. ---
    Probe("readelf", "tool",
          "Read a native handler's dynamic symbols (and c++filt demangles them) for "
          "the ELF-symbol COD scan -- the portable half of attribution.",
          "The native-server / HAL in-code (COD) scan cannot run; attribution is "
          "limited to the ioctl decode and the deferred jadx/ghidra passes.",
          "binutils", required=False),
    Probe("jadx", "tool",
          "Decompile framework services.jar and APKs (the jadx half of attribution): "
          "read Stub/onTransact permission checks that gate binder transactions.",
          "Cannot resolve the in-code (COD) gate for framework (system_server) "
          "services; native-server COD via the ELF-symbol scan still works.",
          "unpack from github.com/skylot/jadx (set SESURFACE_JADX or ~/jadx/bin/jadx)",
          required=False, env="SESURFACE_JADX",
          paths=["~/jadx/bin/jadx", "/opt/jadx/bin/jadx"]),
    Probe("analyzeHeadless", "tool",
          "Ghidra headless: deepen a native handler's COD result from 'a caller "
          "check exists in the library' to 'this function calls it' (call sites).",
          "Attribution falls back to the ELF dynamic-symbol scan (medium confidence) "
          "with no call-site confirmation.",
          "unpack Ghidra (set SESURFACE_GHIDRA to its dir, or ~/ghidra_*_PUBLIC)",
          required=False, env="SESURFACE_GHIDRA",
          paths=["~/ghidra_12.2_PUBLIC/support/analyzeHeadless",
                 "/opt/ghidra/support/analyzeHeadless"]),
]


def _present(p: Probe) -> bool:
    """Is this probe's dependency actually available right now?"""
    if p.kind == "binding":
        # importlib.util.find_spec does not execute the module, so it is safe and
        # cheap even for heavy packages like androguard.
        try:
            return importlib.util.find_spec(p.name) is not None
        except (ImportError, ValueError):
            return False
    if shutil.which(p.name) is not None:
        return True
    # Tools not on PATH (jadx, ghidra): honour an env var and well-known locations.
    # The env var may point at the executable itself or at the install root.
    if p.env and os.environ.get(p.env):
        root = os.path.expanduser(os.environ[p.env])
        if os.path.exists(root):
            return True
        for sub in (p.name, os.path.join("bin", p.name),
                    os.path.join("support", p.name)):
            if os.path.exists(os.path.join(root, sub)):
                return True
    return any(os.path.exists(os.path.expanduser(c)) for c in p.paths)


@dataclass
class DoctorReport:
    """Result of a full environment scan."""
    present: list[Probe]
    missing: list[Probe]

    @property
    def core_ok(self) -> bool:
        """True if every `required` probe is present (analysis can run at all)."""
        return not any(p.required for p in self.missing)


def run_doctor() -> DoctorReport:
    """Scan the environment. Pure computation; printing is the caller's job."""
    present, missing = [], []
    for p in PROBES:
        (present if _present(p) else missing).append(p)
    return DoctorReport(present=present, missing=missing)


def format_report(rep: DoctorReport) -> str:
    """Render a human-readable summary of what works and what degrades."""
    lines: list[str] = ["sesurface environment check", "=" * 26, ""]

    lines.append("Present:")
    if rep.present:
        for p in rep.present:
            lines.append(f"  [ok]   {p.name:<12} {p.kind:<8} -- {p.enables}")
    else:
        lines.append("  (nothing found)")
    lines.append("")

    lines.append("Missing:")
    if rep.missing:
        for p in rep.missing:
            tag = "REQUIRED" if p.required else "optional"
            lines.append(f"  [--]   {p.name:<12} {p.kind:<8} ({tag})")
            lines.append(f"           degrades: {p.degrades}")
            lines.append(f"           install : {p.apt}")
    else:
        lines.append("  (none -- fully provisioned)")
    lines.append("")

    if rep.core_ok:
        lines.append("Core analysis CAN run (all required dependencies present).")
    else:
        need = ", ".join(p.name for p in rep.missing if p.required)
        lines.append(f"Core analysis is BLOCKED -- missing required: {need}.")
        lines.append("Run scripts/bootstrap-ubuntu.sh on Ubuntu 24.04/26.04 to install everything.")

    return "\n".join(lines)
