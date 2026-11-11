"""Tests for the ramdisk reader: newc cpio parse + LZ4-legacy/gzip decompress."""

from __future__ import annotations

import gzip
import struct

import pytest

from sesurface.model.inode import InodeIndex
from sesurface.model.ramdisk import _decompress, _iter_cpio_newc, index_ramdisk


def _newc_entry(name: str, mode: int, data: bytes = b"") -> bytes:
    """One newc (070701) cpio record (no trailing padding of the stream)."""
    name_b = name.encode() + b"\x00"
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_b), 0]
    hdr = b"070701" + b"".join(b"%08x" % x for x in fields)
    rec = bytearray(hdr + name_b)
    while len(rec) % 4:
        rec += b"\x00"
    rec += data
    while len(rec) % 4:
        rec += b"\x00"
    return bytes(rec)


def _newc_archive(entries) -> bytes:
    blob = b"".join(_newc_entry(*e) for e in entries)
    blob += _newc_entry("TRAILER!!!", 0)
    return blob


def test_cpio_newc_parse():
    arc = _newc_archive([
        ("init", 0o100755, b"ELF"),
        ("system", 0o040755),
        ("system/bin", 0o040755),
        ("system/bin/adbd", 0o100755, b"ADBD-BYTES"),
    ])
    got = {name: (mode, data) for name, mode, _u, _g, data in _iter_cpio_newc(arc)}
    assert set(got) == {"init", "system", "system/bin", "system/bin/adbd"}
    assert got["system/bin/adbd"] == (0o100755, b"ADBD-BYTES")
    assert got["init"][1] == b"ELF"


def test_decompress_raw_and_gzip():
    arc = _newc_archive([("init", 0o100755, b"X")])
    assert _decompress(arc) == arc                 # already cpio
    assert _decompress(gzip.compress(arc)) == arc  # gzip


def test_decompress_lz4_legacy():
    lz4 = pytest.importorskip("lz4.block")
    arc = _newc_archive([("init", 0o100755, b"hello ramdisk")])
    block = lz4.compress(arc, store_size=False)
    frame = b"\x02\x21\x4c\x18" + struct.pack("<I", len(block)) + block
    assert _decompress(frame) == arc


def test_index_ramdisk_merges_without_clobber(tmp_path):
    """Ramdisk entries index at the device root and never overwrite existing paths."""
    lz4 = pytest.importorskip("lz4.block")
    arc = _newc_archive([
        ("init", 0o100755, b"ELF"),
        ("system/bin/adbd", 0o100755, b"ADBD"),
    ])
    block = lz4.compress(arc, store_size=False)
    frame = b"\x02\x21\x4c\x18" + struct.pack("<I", len(block)) + block
    (tmp_path / "ramdisk.img").write_bytes(frame)

    idx = InodeIndex()
    from sesurface.model.inode import InodeMeta
    # A pre-existing partition entry for adbd must win over the ramdisk stub.
    idx.meta["/system/bin/adbd"] = InodeMeta(uid=0, gid=0, mode=0o100755,
                                             setype="adbd_exec", caps=None)
    notes = index_ramdisk(str(tmp_path), idx)
    assert "/init" in idx.meta
    assert idx.meta["/init"].mode == 0o100755
    # Not clobbered: still carries the partition's setype, not the ramdisk's None.
    assert idx.meta["/system/bin/adbd"].setype == "adbd_exec"
    assert any("indexed" in n for n in notes)
