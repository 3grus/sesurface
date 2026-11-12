"""Index the boot ramdisk's entries (cpio), mounted at the device root.

`ramdisk.img` is a cpio archive, usually compressed (gzip, or the LZ4 *legacy* frame
format Android bootimg uses). `build_partition_set` cannot treat it as a block
filesystem, so it was flagged "unrecognised filesystem" and skipped. The ramdisk is
the device's first-stage root (`/`), so its entries belong at the device root --
`/init` and, on some builds, the first-stage copies of early daemons.

This parser is deliberately dependency-light and read-only: stdlib `gzip` plus a
small LZ4-legacy decoder (via the `lz4` binding, which is already a transitive dep of
the toolchain) and a hand-rolled `newc` (070701) cpio reader. It contributes uid/gid/
mode for each entry (cpio carries no SELinux xattr, so labels stay `None` -- honestly
unknown, resolved from `file_contexts` elsewhere if at all). Entries are added only
where the path is not already indexed, so the authoritative partition content (e.g.
the real `/system`) always wins over a ramdisk mount-point stub.

On the reference emulator image the ramdisk holds only `init` (adbd/crash_dump ship
in APEX here, resolved by `model/apex.py`); the value is removing a silent gap and
covering builds whose ramdisk does carry early binaries.
"""

from __future__ import annotations

import gzip
import os
import stat as stmod
import struct
from typing import Optional

from .inode import InodeIndex, InodeMeta

_LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"     # 0x184C2102, LZ4 legacy frame.
_GZIP_MAGIC = b"\x1f\x8b"
_CPIO_NEWC_MAGIC = b"070701"
_LZ4_MAX_BLOCK = 8 * 1024 * 1024            # LZ4 legacy: 8 MiB max uncompressed block.


def _decompress(data: bytes) -> Optional[bytes]:
    """Decompress a ramdisk image to its raw cpio, or None if format unknown.

    Handles a raw (already-cpio) image, gzip, and the LZ4 *legacy* frame format
    (a magic followed by [u32 block-size][block] runs, each block an LZ4 raw block).
    """
    if data[:6] == _CPIO_NEWC_MAGIC:
        return data
    if data[:2] == _GZIP_MAGIC:
        try:
            return gzip.decompress(data)
        except OSError:
            return None
    if data[:4] == _LZ4_LEGACY_MAGIC:
        return _lz4_legacy_decompress(data)
    return None


def _lz4_legacy_decompress(data: bytes) -> Optional[bytes]:
    try:
        import lz4.block  # type: ignore
    except ImportError:
        return None
    out = bytearray()
    off = 4
    while off + 4 <= len(data):
        bsize, = struct.unpack_from("<I", data, off)
        off += 4
        # A new magic (next concatenated frame) or a zero size ends the stream.
        if bsize == 0 or bsize == 0x184C2102 or off + bsize > len(data):
            break
        try:
            out += lz4.block.decompress(data[off:off + bsize],
                                        uncompressed_size=_LZ4_MAX_BLOCK)
        except Exception:
            return None
        off += bsize
    return bytes(out) if out else None


def _iter_cpio_newc(blob: bytes):
    """Yield (path, mode, uid, gid, data_bytes) for each newc cpio entry."""
    pos = 0
    n = len(blob)
    while pos + 110 <= n:
        if blob[pos:pos + 6] != _CPIO_NEWC_MAGIC:
            break
        fields = [int(blob[pos + 6 + i * 8: pos + 6 + (i + 1) * 8], 16)
                  for i in range(13)]
        (_ino, mode, uid, gid, _nlink, _mtime, filesize, _devmaj, _devmin,
         _rdevmaj, _rdevmin, namesize, _check) = fields
        name_start = pos + 110
        name = blob[name_start:name_start + namesize - 1].decode("latin1")
        # Name field is padded to a 4-byte boundary from the record start.
        data_start = name_start + namesize
        data_start += (-data_start) % 4
        data = blob[data_start:data_start + filesize]
        next_pos = data_start + filesize
        next_pos += (-next_pos) % 4
        pos = next_pos
        if name == "TRAILER!!!":
            break
        if name in (".", ""):
            continue
        yield (name, mode, uid, gid, data)


def _ramdisk_from_boot(boot_path: str) -> Optional[bytes]:
    """The (compressed) ramdisk cpio embedded in a boot/vendor_boot image, or None."""
    from .bootimg import parse_boot_image
    try:
        with open(boot_path, "rb") as f:
            bi = parse_boot_image(f.read())
    except OSError:
        return None
    return bi.ramdisk if bi is not None else None


def index_ramdisk(image_dir: str, idx: InodeIndex) -> list[str]:
    """Parse every ramdisk image in `image_dir` and merge its entries into `idx`.

    Entries mount at the device root (`/init`, ...) and never overwrite an existing
    index entry, so partition content stays authoritative. Returns short notes.
    """
    notes: list[str] = []
    try:
        all_imgs = os.listdir(image_dir)
    except OSError:
        return notes
    # Standalone ramdisk images, plus the ramdisks embedded in boot containers.
    rd_names = [f for f in all_imgs if f.endswith(".img") and "ramdisk" in f]
    boot_names = [f for f in all_imgs
                  if f in ("boot.img", "init_boot.img", "vendor_boot.img")]
    sources: list[tuple[str, bytes]] = []
    for fname in sorted(rd_names):
        try:
            with open(os.path.join(image_dir, fname), "rb") as f:
                sources.append((fname, f.read()))
        except OSError:
            continue
    for fname in sorted(boot_names):
        blob = _ramdisk_from_boot(os.path.join(image_dir, fname))
        if blob is not None:
            sources.append((f"{fname}:ramdisk", blob))

    for fname, raw in sources:
        cpio = _decompress(raw)
        if cpio is None:
            notes.append(f"ramdisk: {fname} is not a recognised cpio/gzip/lz4 image")
            continue
        count = 0
        for name, mode, uid, gid, _data in _iter_cpio_newc(cpio):
            dev_path = "/" + name.lstrip("/")
            if dev_path in idx.meta:
                continue        # partition content wins over a ramdisk stub
            idx.meta[dev_path] = InodeMeta(
                uid=uid, gid=gid, mode=mode, setype=None, caps=None,
                is_dir=stmod.S_ISDIR(mode), is_symlink=stmod.S_ISLNK(mode))
            count += 1
        notes.append(f"ramdisk: indexed {count} entr(ies) from {fname}")
    return notes
