"""Tests for Android sparse-image expansion (the pure-Python path)."""

from __future__ import annotations

import struct

from sesurface.model.sparse import SPARSE_MAGIC, _desparse_py, is_sparse


def _sparse(blk_sz, chunks):
    """Build a sparse image from (chunk_type, blocks, payload) tuples."""
    body = b""
    total_blks = 0
    for ctype, blocks, payload in chunks:
        total_blks += blocks
        ch = struct.pack("<HHII", ctype, 0, blocks, 12 + len(payload))
        body += ch + payload
    hdr = struct.pack("<IHHHHIIII", SPARSE_MAGIC, 1, 0, 28, 12, blk_sz,
                      total_blks, len(chunks), 0)
    return hdr + body


def test_is_sparse(tmp_path):
    p = tmp_path / "s.img"
    p.write_bytes(_sparse(4096, [(0xCAC1, 1, b"\x11" * 4096)]))
    assert is_sparse(str(p))
    q = tmp_path / "r.img"
    q.write_bytes(b"\x00" * 4096)
    assert not is_sparse(str(q))


def test_desparse_all_chunk_types(tmp_path):
    blk = 4096
    raw_block = b"\xAB" * blk
    img = _sparse(blk, [
        (0xCAC1, 1, raw_block),           # RAW
        (0xCAC2, 2, b"\xCD\xCD\xCD\xCD"),  # FILL, 2 blocks of 0xCD
        (0xCAC3, 1, b""),                  # DONT_CARE -> zeros
    ])
    src = tmp_path / "sys.img"
    src.write_bytes(img)
    dst = tmp_path / "out.raw"
    assert _desparse_py(str(src), str(dst))
    out = dst.read_bytes()
    assert out[:blk] == raw_block
    assert out[blk:3 * blk] == b"\xCD" * (2 * blk)
    assert out[3 * blk:4 * blk] == b"\x00" * blk
    assert len(out) == 4 * blk


def test_desparse_rejects_nonsparse(tmp_path):
    src = tmp_path / "x.img"
    src.write_bytes(b"not sparse" * 100)
    dst = tmp_path / "out.raw"
    assert _desparse_py(str(src), str(dst)) is False
