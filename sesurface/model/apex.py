"""Mount APEX payloads so `/apex/<pkg>/...` resolves like any other partition.

An APEX module (`/system/apex/com.android.*.apex`, often `.capex` = compressed) is a
zip whose `apex_payload.img` is a small filesystem (ext4 here; EROFS on some builds)
holding `./bin`, `./lib64`, `./javalib`, `./etc` and an `apex_manifest.pb`. At runtime
it is loopback-mounted at `/apex/<package>/`, where `<package>` is the manifest name --
which can differ from the container filename, so we read it rather than guess.

Two whole analyses were blocked on this being unreadable:

  * **Native daemons.** `statsd`, `mediatranscoding`, `adbd`, `crash_dump` and friends
    ship as `/apex/<pkg>/bin/*`. Their SELinux exec label (e.g. `statsd_exec`) lives in
    the payload's xattrs; once indexed, the locator's exec-type -> binary map resolves
    the daemon and the ELF COD scan runs -- no attribution-logic change.
  * **Framework services in Java.** `/apex/<pkg>/javalib/service-*.jar` holds the
    framework services that are *not* in `services.jar` (appsearch, tethering/
    connectivity, wifi, uwb, permission, ...). Decompiled like `services.jar`, they
    feed straight into the existing `FrameworkAnalyzer`.

We realise each payload as an ordinary `Partition` mounted at `/apex/<package>`, so the
existing inode indexer, `ImageFiles` resolver, and extractor handle it unchanged.

Untrusted-data hygiene: APEX contents are untrusted firmware. We open the zip with the
stdlib (never execute it), extract the payload into an isolated work dir, and pass
paths as arguments downstream.
"""

from __future__ import annotations

import json
import os
import zipfile
from typing import Optional

from .extract import ImageFiles
from .inode import InodeIndex, index_partition
from .partitions import Partition, PartitionSet, _sniff_fs

# APEX containers live under `<mount>/apex/` on each updatable partition.
_APEX_SUFFIXES = (".apex", ".capex")


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a protobuf varint at `pos`; return (value, next_pos)."""
    result = shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def parse_apex_manifest(data: bytes) -> Optional[str]:
    """The package name from an `apex_manifest.pb` (protobuf field 1, a string).

    `ApexManifest` field 1 (`name`) is a length-delimited string, i.e. tag byte 0x0A
    then a varint length then the UTF-8 bytes. We read just that field; the rest
    (version, provideNativeLibs, ...) is irrelevant to the mount point.
    """
    if len(data) < 2 or data[0] != 0x0A:
        return None
    length, pos = _read_varint(data, 1)
    if length <= 0 or pos + length > len(data):
        return None
    name = data[pos:pos + length].decode("utf-8", "replace").strip("\x00")
    return name or None


def _payload_from_zip(z: zipfile.ZipFile, work: str) -> Optional[tuple[str, str]]:
    """From an opened APEX/compressed-APEX zip, return (package, payload_img_path)."""
    names = set(z.namelist())
    # A `.capex` wraps the real `.apex` as `original_apex`; unwrap one level.
    if "original_apex" in names:
        inner = os.path.join(work, "original_apex")
        with open(inner, "wb") as f:
            f.write(z.read("original_apex"))
        try:
            z = zipfile.ZipFile(inner)
        except (zipfile.BadZipFile, OSError):
            return None
        names = set(z.namelist())
    if "apex_payload.img" not in names:
        return None
    pkg: Optional[str] = None
    if "apex_manifest.pb" in names:
        pkg = parse_apex_manifest(z.read("apex_manifest.pb"))
    if not pkg and "apex_manifest.json" in names:
        try:
            pkg = (json.loads(z.read("apex_manifest.json")) or {}).get("name")
        except (ValueError, TypeError):
            pkg = None
    if not pkg:
        return None
    payload = os.path.join(work, "apex_payload.img")
    with open(payload, "wb") as f:
        f.write(z.read("apex_payload.img"))
    return pkg, payload


def _discover_containers(idx: InodeIndex) -> list[str]:
    """On-device paths of every APEX container, from the inode index."""
    out = []
    for path, meta in idx.meta.items():
        if path.endswith(_APEX_SUFFIXES) and "/apex/" in path and not meta.is_dir:
            out.append(path)
    return sorted(out)


def index_apex_partitions(ps: PartitionSet, files: ImageFiles, idx: InodeIndex,
                          work_dir: str, read_labels: bool = True) -> list[str]:
    """Mount every APEX payload as a partition and merge its inodes into `idx`.

    Returns human-readable notes (packages mounted, containers skipped). The carved
    payload images are kept under `work_dir/apex/` and reused on later runs, the same
    as top-level partitions.
    """
    notes: list[str] = []
    apex_out = os.path.join(work_dir, "apex")
    tmp = os.path.join(work_dir, "apex-tmp")
    os.makedirs(apex_out, exist_ok=True)
    os.makedirs(tmp, exist_ok=True)

    mounted = 0
    for dev_path in _discover_containers(idx):
        container = os.path.join(tmp, os.path.basename(dev_path))
        if not files.extract_to(dev_path, container):
            notes.append(f"apex: could not read container {dev_path}")
            continue
        try:
            z = zipfile.ZipFile(container)
        except (zipfile.BadZipFile, OSError):
            # A flattened APEX is a directory, not a zip; its files are already in the
            # partition tree under /apex/<pkg>/ and need no separate mount.
            notes.append(f"apex: {os.path.basename(dev_path)} is not a zip "
                         "(flattened or unreadable); skipped")
            continue
        got = _payload_from_zip(z, tmp)
        if got is None:
            notes.append(f"apex: no payload/manifest in {os.path.basename(dev_path)}")
            continue
        pkg, payload = got
        dst = os.path.join(apex_out, f"{pkg}.img")
        os.replace(payload, dst)
        fstype = _sniff_fs(dst)
        part = Partition(name=f"apex:{pkg}", image=dst, fstype=fstype,
                         mountpoint=f"/apex/{pkg}")
        if part.name in ps.partitions:
            continue
        ps.partitions[part.name] = part
        if index_partition(idx, part, read_labels=read_labels):
            mounted += 1
        else:
            notes.append(f"apex: {pkg} payload is {fstype} (not indexable)")
    # Best-effort cleanup of the scratch container/payload copies.
    try:
        for name in os.listdir(tmp):
            os.remove(os.path.join(tmp, name))
        os.rmdir(tmp)
    except OSError:
        pass
    notes.insert(0, f"apex: mounted {mounted} payload(s) under /apex/")
    return notes
