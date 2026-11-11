#!/usr/bin/env bash
# Fetch an AOSP emulator system image to use as a correctness fixture.
#
# The AOSP ("android" tag) emulator images are full Treble builds: split SELinux
# policy (CIL + precompiled), VINTF manifests, APEXes and init .rc files -- exactly
# the artifacts sesurface analyses, with a known-good `sesearch`/`seinfo` to check
# against. We use the no-GMS "android" tag so the policy is clean AOSP.
#
# Images land under images/<name>/ (git-ignored). The download is checksum-verified.
#
# Usage:
#   scripts/fetch-aosp-image.sh                 # default: API 33, x86_64
#   scripts/fetch-aosp-image.sh 31 x86_64       # another API level / arch
#
# To add a new (api, arch): look up the zip name + sha1 in
#   https://dl.google.com/android/repository/sys-img/android/sys-img2-1.xml
# and extend the table below.
set -euo pipefail
cd "$(dirname "$0")/.."

API="${1:-33}"
ARCH="${2:-x86_64}"

# (api arch) -> "zipname sha1". Verified against sys-img2-1.xml.
declare -A ZIP=(
    ["33 x86_64"]="x86_64-33_r02.zip d4698590184a21fe1e8754284130ad3006b5fc79"
    ["31 x86_64"]="x86_64-31_r05.zip"   # sha1 TBD: fill from the index before use
    ["34 x86_64"]="x86_64-34_r04.zip"   # sha1 TBD
)
key="$API $ARCH"
entry="${ZIP[$key]:-}"
if [[ -z "$entry" ]]; then
    echo "No known image for '$key'. Add it to the table in this script." >&2
    exit 1
fi
read -r ZIPNAME SHA1 <<<"$entry"

BASE="https://dl.google.com/android/repository/sys-img/android"
OUT="images/aosp-api${API}-${ARCH}"
mkdir -p "$OUT"

echo ">> Downloading $ZIPNAME (~660MB) ..."
curl -L --fail --continue-at - --max-time 1800 \
     -o "$OUT/$ZIPNAME" "$BASE/$ZIPNAME"

if [[ -n "${SHA1:-}" && "$SHA1" != "TBD" ]]; then
    echo ">> Verifying sha1 ..."
    echo "$SHA1  $OUT/$ZIPNAME" | sha1sum -c -
else
    echo ">> WARNING: no sha1 on record for $key; skipping integrity check." >&2
fi

echo ">> Unzipping ..."
# The zip expands to a top-level '<arch>/' dir containing system.img, vendor.img,
# ramdisk.img, etc. Extract into OUT/ and report what came out.
( cd "$OUT" && unzip -o -q "$ZIPNAME" )

echo ">> Contents:"
find "$OUT" -maxdepth 2 -type f ! -name '*.zip' -printf '   %P  (%s bytes)\n' | sort

echo ">> Done. Image root: $OUT"
echo "   Note: emulator *.img may be raw ext4, sparse, or QCOW2-wrapped; the"
echo "   build-image stage sniffs and converts as needed (simg2img / raw loop)."
