"""Reconstruct the device's partition layout from image files.

Every rule sesurface analyses refers to on-device paths (`/vendor/bin/hw/foo`,
`/dev/binder`). The files on disk look different: a handful of `*.img` files, each
possibly a GPT disk wrapping a `super` dynamic-partition container wrapping the
real filesystems. This module turns those images into a set of carved, directly
readable filesystem partitions plus the map from each to its on-device mountpoint.

What it does, in order:
  1. Parse each image's GPT (if any) to find its partitions.
  2. If a partition is a liblp `super` container, parse it (`superimg.py`) into its
     logical partitions. Otherwise treat the partition as a filesystem directly.
  3. Carve each filesystem partition to its own file (so `debugfs`/`dump.erofs`,
     which have no offset option, can read it), unless already carved (cached).
  4. Sniff each partition's filesystem type (ext4 vs EROFS).

The result is a `PartitionSet`: partition name -> (carved image path, fs type,
on-device mountpoint). Everything downstream reads through this.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from .sparse import desparse, is_sparse
from .superimg import parse_super

# Partition name -> on-device mountpoint. Names come from GPT/liblp; mountpoints are
# the Treble standard. A name we do not recognise is mounted at /<name>.
MOUNTPOINTS = {
    "system": "/system",
    "system_ext": "/system_ext",
    "product": "/product",
    "vendor": "/vendor",
    "odm": "/odm",
    "vendor_dlkm": "/vendor_dlkm",
    "odm_dlkm": "/odm_dlkm",
    "system_dlkm": "/system_dlkm",
}

# Filesystem superblock magics.
_EXT_MAGIC = b"\x53\xef"            # at byte 0x438 (little-endian 0xEF53).
_EROFS_MAGIC = b"\xe2\xe1\xf5\xe0"  # 0xE0F5E1E2 LE, at byte 0x400.
_F2FS_MAGIC = b"\x10\x20\xf5\xf2"   # 0xF2F52010 LE, at byte 0x400 (userdata/metadata).


@dataclass(frozen=True)
class Partition:
    """One carved, readable filesystem partition."""
    name: str
    image: str              # Path to the carved filesystem image on disk.
    fstype: str             # "ext4" | "erofs" | "unknown".
    mountpoint: str         # On-device absolute path, e.g. "/vendor".


@dataclass
class PartitionSet:
    """All partitions of one firmware image, plus how it was laid out."""
    partitions: dict[str, Partition] = field(default_factory=dict)
    # True when the root filesystem is the system partition (system-as-root), i.e.
    # the device's "/" is system.img's root and /system is one level inside it.
    system_as_root: bool = True
    notes: list[str] = field(default_factory=list)

    def by_mountpoint(self) -> dict[str, Partition]:
        return {p.mountpoint: p for p in self.partitions.values()}


# --------------------------------------------------------------------------- #
# GPT parsing (just enough to find partitions by name and offset).
# --------------------------------------------------------------------------- #

def _parse_gpt(path: str) -> list[tuple[str, int, int]]:
    """Return [(name, start_byte, size_byte)] for a GPT disk image, or [] if none.

    GPT: an LBA-sized protective MBR, then the GPT header at LBA 1, then an array of
    partition entries whose location/size/count the header gives. Each entry is 128
    bytes: type GUID, unique GUID, first LBA, last LBA, attributes, then a 72-byte
    UTF-16LE name. We assume 512-byte logical sectors (true for these images).
    """
    SECTOR = 512
    with open(path, "rb") as f:
        f.seek(SECTOR)                      # LBA 1: GPT header.
        hdr = f.read(SECTOR)
        if hdr[:8] != b"EFI PART":
            return []
        part_entry_lba, = struct.unpack_from("<Q", hdr, 72)
        num_entries, = struct.unpack_from("<I", hdr, 80)
        entry_size, = struct.unpack_from("<I", hdr, 84)
        f.seek(part_entry_lba * SECTOR)
        table = f.read(num_entries * entry_size)

    out: list[tuple[str, int, int]] = []
    ZERO_GUID = b"\x00" * 16
    for i in range(num_entries):
        rec = table[i * entry_size: i * entry_size + entry_size]
        if len(rec) < 128 or rec[:16] == ZERO_GUID:
            continue                        # Unused entry.
        first_lba, last_lba = struct.unpack_from("<QQ", rec, 32)
        name = rec[56:128].decode("utf-16-le", "replace").split("\x00")[0]
        start = first_lba * SECTOR
        size = (last_lba - first_lba + 1) * SECTOR
        out.append((name, start, size))
    return out


def _has_lp_geometry(path: str, offset: int) -> bool:
    """True if a liblp super geometry magic sits at `offset` in `path`."""
    try:
        with open(path, "rb") as f:
            f.seek(offset + 4096)           # Geometry follows the 4096-byte reserved area.
            return f.read(4) == struct.pack("<I", 0x616C4467)
    except OSError:
        return False


def _sniff_fs(path: str) -> str:
    """Identify a carved partition's filesystem from its superblock magic."""
    try:
        with open(path, "rb") as f:
            f.seek(0x400)
            head = f.read(0x40)             # Covers EROFS (0x400) and ext (0x438) magics.
    except OSError:
        return "unknown"
    if head[0:4] == _EROFS_MAGIC:
        return "erofs"
    if head[0:4] == _F2FS_MAGIC:            # f2fs superblock magic at 0x400.
        return "f2fs"
    if head[0x38:0x3A] == _EXT_MAGIC:       # 0x438 - 0x400 = 0x38.
        return "ext4"
    return "unknown"


def _carve(src: str, offset: int, size: int, dst: str) -> None:
    """Copy `size` bytes at `offset` from `src` to `dst` (a carved partition image).

    Skipped if `dst` already exists at the right size, so re-running build-image is
    cheap. Uses a chunked copy rather than loading the whole partition into memory.
    """
    if os.path.exists(dst) and os.path.getsize(dst) == size:
        return
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fin.seek(offset)
        remaining = size
        chunk = 8 * 1024 * 1024
        while remaining > 0:
            buf = fin.read(min(chunk, remaining))
            if not buf:
                break
            fout.write(buf)
            remaining -= len(buf)


def build_partition_set(image_dir: str, work_dir: str) -> PartitionSet:
    """Carve every filesystem partition from the images in `image_dir`.

    `image_dir` holds the raw `*.img` files (e.g. system.img, vendor.img). Carved
    partitions are written under `work_dir` and reused on subsequent runs. Returns a
    `PartitionSet` describing what was found.
    """
    os.makedirs(work_dir, exist_ok=True)
    ps = PartitionSet()

    imgs = sorted(f for f in os.listdir(image_dir) if f.endswith(".img"))
    for img in imgs:
        path = os.path.join(image_dir, img)
        # Normalise an Android sparse image to raw first (it is not a readable
        # filesystem until expanded). The raw output is still read in place, so DAC
        # ground truth is preserved. Boot/ramdisk images are handled elsewhere.
        if img[:-4] not in ("boot", "vendor_boot", "init_boot", "ramdisk") \
                and is_sparse(path):
            raw = os.path.join(work_dir, f"{img[:-4]}.raw.img")
            if desparse(path, raw):
                path = raw
                ps.notes.append(f"expanded sparse image {img} -> {os.path.basename(raw)}")
            else:
                ps.notes.append(f"sparse image {img} could not be expanded; skipped")
                continue
        gpt = _parse_gpt(path)
        # Candidate (name, offset, size) regions to interpret as super or filesystem.
        regions = gpt if gpt else [(img[:-4], 0, os.path.getsize(path))]

        for name, offset, size in regions:
            if _has_lp_geometry(path, offset):
                # A super container: expand to its logical partitions and carve each.
                for lp in parse_super(path, offset):
                    if lp.size == 0:
                        continue
                    _add_logical(ps, path, lp, work_dir)
            elif name in ("vbmeta", "vbmeta_system", "metadata", "userdata", "cache",
                          "encryptionkey"):
                # Not a filesystem we analyse; skip quietly.
                continue
            elif name in ("ramdisk", "boot", "vendor_boot", "init_boot"):
                # A boot/ramdisk image (cpio, often gzip/lz4-compressed), not a block
                # filesystem. Indexed separately by `model/ramdisk.py`, which parses
                # the cpio and mounts its entries at the device root.
                continue
            else:
                # A direct filesystem partition (e.g. vendor.img's "vendor").
                dst = os.path.join(work_dir, f"{name}.img")
                _carve(path, offset, size, dst)
                _register(ps, name, dst)

    _finalize(ps)
    return ps


def _add_logical(ps: PartitionSet, src: str, lp, work_dir: str) -> None:
    """Carve one logical partition (possibly multi-extent) and register it."""
    dst = os.path.join(work_dir, f"{lp.name}.img")
    if not (os.path.exists(dst) and os.path.getsize(dst) == lp.size):
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            for off, length in lp.extents:
                fin.seek(off)
                remaining = length
                while remaining > 0:
                    buf = fin.read(min(8 * 1024 * 1024, remaining))
                    if not buf:
                        break
                    fout.write(buf)
                    remaining -= len(buf)
    _register(ps, lp.name, dst)


def _register(ps: PartitionSet, name: str, image: str) -> None:
    """Record a carved partition, skipping duplicates (first one wins).

    Duplicates happen because the emulator ships a `vendor` both inside system.img's
    super and as a standalone vendor.img. We keep the first seen and note it.
    """
    if name in ps.partitions:
        ps.notes.append(f"duplicate partition '{name}' ignored (kept first)")
        return
    fstype = _sniff_fs(image)
    mountpoint = MOUNTPOINTS.get(name, f"/{name}")
    ps.partitions[name] = Partition(name=name, image=image, fstype=fstype,
                                    mountpoint=mountpoint)


def _finalize(ps: PartitionSet) -> None:
    """Fill in layout facts that depend on the whole set."""
    if "system" not in ps.partitions:
        ps.notes.append("no 'system' partition found -- image layout is unexpected")
    for p in ps.partitions.values():
        if p.fstype == "f2fs":
            # f2fs is the read-write data format (userdata/metadata/cache). It holds no
            # read-only system content the analysis needs, and is not read here.
            ps.notes.append(
                f"partition '{p.name}' ({p.mountpoint}) is f2fs (read-write data); "
                "not analysed -- expected, holds no system/policy content")
        elif p.fstype == "unknown":
            ps.notes.append(
                f"partition '{p.name}' ({p.mountpoint}) has an unrecognised filesystem "
                "-- its files, labels and inodes are NOT indexed. If this holds "
                "system/vendor content, that content is missing from the analysis "
                "(it may be a still-compressed/sparse image, an encrypted partition, "
                "or an fs type sesurface does not read).")
