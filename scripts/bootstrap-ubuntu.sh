#!/usr/bin/env bash
# Bootstrap sesurface's environment on Ubuntu 24.04 / 26.04.
#
# sesurface needs machinery that is not pip-installable: the real SELinux toolkit
# (setools + libselinux bindings + the secilc CIL compiler) and a few filesystem
# extractors. Those come from apt. Everything else (androguard) is a normal pip
# dependency installed into a uv venv.
#
# The one subtlety: the venv is created with --system-site-packages so the
# apt-installed python3-setools / python3-selinux modules are importable from it.
# A plain `uv venv` would hide them.
#
# This script is idempotent: re-running it is safe and just reconciles state.
# Package names below are verified against Ubuntu 24.04 (noble).
#
# Usage:
#   scripts/bootstrap-ubuntu.sh            # full setup (apt needs sudo)
#   scripts/bootstrap-ubuntu.sh --venv-only   # skip apt, just (re)build the venv
#
# apt requires root; if you are not root the script calls sudo, which may prompt
# for your password. Run the whole thing with `! scripts/bootstrap-ubuntu.sh`
# from the Claude Code prompt so the password prompt reaches you.
set -euo pipefail

cd "$(dirname "$0")/.."

VENV_ONLY=0
[[ "${1:-}" == "--venv-only" ]] && VENV_ONLY=1

SUDO=""
if [[ $EUID -ne 0 ]]; then SUDO="sudo"; fi

# Packages that exist on noble and that we actually use. Grouped by purpose.
APT_PKGS=(
    python3-setools          # SELinux policy parsing (the core engine) -- the setools LIBRARY.
    setools                  # sesearch/seinfo/sediff CLIs (for cross-checking results).
    secilc                   # compile split CIL policy when no precompiled binary applies.
    libselinux1              # libselinux runtime.
    python3-selinux          # selabel bindings (runtime-path label lookup).
    e2fsprogs                # debugfs: read true inode metadata from ext4 without mounting.
    erofs-utils              # dump.erofs/fsck.erofs: same for EROFS (Android 13+).
    attr                     # getfattr: read SELinux xattrs from a loop-mount.
    android-sdk-libsparse-utils  # simg2img: Android sparse image -> raw.
)
# NOT available as an apt package on noble (needed only for super.img dynamic
# partitions, which the AOSP emulator image does not use):
#   lpunpack  -> build from AOSP platform/system/extras, or use a Python unpacker.

if [[ $VENV_ONLY -eq 0 ]]; then
    echo ">> Installing system packages (apt; may prompt for sudo) ..."
    $SUDO apt-get update
    $SUDO apt-get install -y "${APT_PKGS[@]}"
else
    echo ">> --venv-only: skipping apt."
fi

echo ">> Creating uv venv with access to the system SELinux bindings ..."
# --system-site-packages is REQUIRED: python3-setools lives in the system
# interpreter's site-packages and cannot be pip-installed into an isolated venv.
uv venv --system-site-packages

echo ">> Installing sesurface and its pip dependencies ..."
uv sync

# --- Attribution tools (stage H): jadx + ghidra ------------------------------
# These are NOT apt packages -- they are release archives you unpack once. The
# attribution pass (`sesurface attribute`) finds them via $SESURFACE_JADX / $SESURFACE_GHIDRA
# or the default ~/jadx and ~/ghidra_*_PUBLIC locations; `sesurface doctor` reports them.
# The native-server COD scan works without them (ELF symbols); jadx is needed for the
# framework (services.jar) half, and ghidra raises native results to call-site confidence.
echo ">> Attribution tools (optional, not apt): jadx + ghidra"
echo "   jadx  : https://github.com/skylot/jadx/releases  -> unpack, set SESURFACE_JADX=<dir>/bin/jadx (or ~/jadx)"
echo "   ghidra: https://github.com/NationalSecurityAgency/ghidra/releases -> unpack, set SESURFACE_GHIDRA=<dir> (or ~/ghidra_*_PUBLIC)"

echo ">> Verifying the environment ..."
uv run sesurface doctor || {
    echo ">> doctor reported missing pieces -- see above." >&2
    exit 1
}

echo ">> Done. Use:  uv run sesurface <subcommand>   (or: source .venv/bin/activate)"
