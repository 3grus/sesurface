"""Tests for the kernel-symbol enrichment: decompression + bounded presence.

The decompressors are exercised with tiny synthetic streams that carry the kernel
banner; the presence scan is tested for bounded (whole-token) matching so a substring
does not count. No real kernel image is needed.
"""

from __future__ import annotations

import gzip
import lzma
import struct

import pytest

from sesurface.model.kallsyms import KernelSymbols, decompress_kernel

_BODY = b"junk before Linux version 5.15.0-test (builder) more junk ashmem_ioctl end"


def test_decompress_gzip():
    blob = b"\x00" * 64 + gzip.compress(_BODY) + b"\xff\xff trailing"
    out, fmt = decompress_kernel(blob)
    assert fmt == "gzip"
    assert b"Linux version" in out


def test_decompress_xz():
    blob = b"PADDING" + lzma.compress(_BODY, format=lzma.FORMAT_XZ)
    out, fmt = decompress_kernel(blob)
    assert fmt == "xz"
    assert b"ashmem_ioctl" in out


def test_decompress_lz4_legacy():
    lz4 = pytest.importorskip("lz4.block")
    block = lz4.compress(_BODY, store_size=False)
    blob = b"\x02\x21\x4c\x18" + struct.pack("<I", len(block)) + block
    out, fmt = decompress_kernel(blob)
    assert fmt == "lz4"
    assert b"Linux version" in out


def test_decompress_unknown_returns_none():
    out, fmt = decompress_kernel(b"not a kernel, no banner, random bytes" * 10)
    assert out is None
    assert fmt == ""


def test_presence_bounded(tmp_path):
    """present() matches a whole-token symbol but not a substring of a larger one."""
    kimg = tmp_path / "kernel"
    kimg.write_bytes(gzip.compress(
        b"Linux version 5.15 \x00ashmem_ioctl\x00 my_ashmem_ioctl_wrapper \x00binder_ioctl\x00"))
    ks = KernelSymbols(str(kimg), str(tmp_path / "cache"))
    assert ks.available()
    assert ks.format == "gzip"
    assert ks.present("ashmem_ioctl") is True
    assert ks.present("binder_ioctl") is True
    assert ks.present("my_ashmem_ioctl_wrapper") is True    # the whole token
    # A name that appears only as a substring of a longer token is NOT present.
    assert ks.present("ashmem_ioctl_wrapper") is False      # inside my_ashmem_ioctl_wrapper
    assert ks.present("shmem_ioctl") is False               # substring of ashmem_ioctl
    assert ks.present("nonexistent_ioctl") is False


def test_presence_skips_placeholder(tmp_path):
    kimg = tmp_path / "kernel"
    kimg.write_bytes(gzip.compress(b"Linux version 5.15 drm stuff"))
    ks = KernelSymbols(str(kimg), str(tmp_path / "cache"))
    # The vendor placeholder handler is not a concrete symbol.
    assert ks.present("<drm_ioctl / vendor KMD>") is False


def test_unavailable_when_no_kernel(tmp_path):
    ks = KernelSymbols(str(tmp_path / "missing"), str(tmp_path / "cache"))
    assert ks.available() is False
    assert ks.present("ashmem_ioctl") is False
    assert ks.address("ashmem_ioctl") is None
