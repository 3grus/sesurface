"""Expand an Android sparse image to a raw filesystem image.

Factory/OTA images ship many partitions in the **Android sparse** format: a run-length
container (`simg2img`'s input) that is *not* itself a filesystem, so `debugfs`/the EROFS
reader cannot read it until it is expanded. This is format normalisation, not tree
extraction -- the output is a raw ext4/EROFS image that the pipeline still reads **in
place**, so the DAC ground truth (uid/gid/mode/xattr straight from the image) is
preserved exactly as for a natively-raw image.

Pure-Python and dependency-free; `simg2img` is used only as a fallback if present. The
format is simple: a 28-byte file header, then chunks (RAW / FILL / DONT_CARE / CRC32).
"""

from __future__ import annotations

import os
import struct
import subprocess

SPARSE_MAGIC = 0xED26FF3A      # stored LE as bytes 3a ff 26 ed
_CHUNK_RAW = 0xCAC1
_CHUNK_FILL = 0xCAC2
_CHUNK_DONT_CARE = 0xCAC3
_CHUNK_CRC32 = 0xCAC4


def is_sparse(path: str) -> bool:
    """True if `path` begins with the Android sparse magic."""
    try:
        with open(path, "rb") as f:
            return struct.unpack("<I", f.read(4))[0] == SPARSE_MAGIC
    except (OSError, struct.error):
        return False


def desparse(src: str, dst: str) -> bool:
    """Expand sparse image `src` to raw image `dst`. Return True on success.

    Skipped if `dst` already exists and is non-empty (cached, like partition carving).
    """
    if os.path.exists(dst) and os.path.getsize(dst) > 0:
        return True
    try:
        if _desparse_py(src, dst):
            return True
    except (OSError, struct.error, ValueError):
        pass
    # Fallback: the system tool, if the pure-Python path failed on an odd variant.
    try:
        import shutil
        if shutil.which("simg2img"):
            subprocess.run(["simg2img", src, dst], capture_output=True, timeout=600,
                           check=True)
            return os.path.exists(dst) and os.path.getsize(dst) > 0
    except (OSError, subprocess.SubprocessError):
        pass
    if os.path.exists(dst) and os.path.getsize(dst) == 0:
        os.remove(dst)
    return False


def _desparse_py(src: str, dst: str) -> bool:
    with open(src, "rb") as fin:
        hdr = fin.read(28)
        if len(hdr) < 28:
            return False
        (magic, _major, _minor, file_hdr_sz, chunk_hdr_sz, blk_sz,
         _total_blks, total_chunks, _checksum) = struct.unpack("<IHHHHIIII", hdr)
        if magic != SPARSE_MAGIC:
            return False
        # Headers may be larger than the base sizes in later minor versions; skip the
        # extra bytes so we land exactly on the first chunk.
        if file_hdr_sz > 28:
            fin.read(file_hdr_sz - 28)
        with open(dst, "wb") as fout:
            for _ in range(total_chunks):
                ch = fin.read(12)
                if len(ch) < 12:
                    break
                ctype, _res, chunk_blks, total_sz = struct.unpack("<HHII", ch)
                if chunk_hdr_sz > 12:
                    fin.read(chunk_hdr_sz - 12)
                out_bytes = chunk_blks * blk_sz
                if ctype == _CHUNK_RAW:
                    remaining = out_bytes
                    while remaining > 0:
                        buf = fin.read(min(1 << 20, remaining))
                        if not buf:
                            break
                        fout.write(buf)
                        remaining -= len(buf)
                elif ctype == _CHUNK_FILL:
                    fill = fin.read(4)
                    fout.write(fill * (out_bytes // 4))
                elif ctype == _CHUNK_DONT_CARE:
                    fout.write(b"\x00" * out_bytes)
                elif ctype == _CHUNK_CRC32:
                    fin.read(4)     # a checksum, no output
                else:
                    # Unknown chunk: skip its body by the declared total size.
                    body = total_sz - chunk_hdr_sz
                    if body > 0:
                        fin.read(body)
    return os.path.getsize(dst) > 0
