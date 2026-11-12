"""Tests for Android boot-image unpacking (ANDROID! v2/v3, VNDRBOOT)."""

from __future__ import annotations

import struct

from sesurface.model.bootimg import parse_boot_image


def _round_up(n, a):
    return (n + a - 1) // a * a


def _android_v2(kernel, ramdisk, page=2048):
    hdr = bytearray(page)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, len(kernel))        # kernel_size
    struct.pack_into("<I", hdr, 16, len(ramdisk))      # ramdisk_size
    struct.pack_into("<I", hdr, 36, page)              # page_size
    struct.pack_into("<I", hdr, 40, 2)                 # header_version
    img = bytes(hdr)
    img += kernel + b"\x00" * (_round_up(len(kernel), page) - len(kernel))
    img += ramdisk + b"\x00" * (_round_up(len(ramdisk), page) - len(ramdisk))
    return img


def _android_v3(kernel, ramdisk):
    page = 4096
    hdr = bytearray(page)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, len(kernel))        # kernel_size
    struct.pack_into("<I", hdr, 12, len(ramdisk))      # ramdisk_size
    struct.pack_into("<I", hdr, 40, 3)                 # header_version
    img = bytes(hdr)
    img += kernel + b"\x00" * (_round_up(len(kernel), page) - len(kernel))
    img += ramdisk
    return img


def _vendor_boot(ramdisk, page=4096, header_size=2112):
    hdr = bytearray(_round_up(header_size, page))
    hdr[0:8] = b"VNDRBOOT"
    struct.pack_into("<I", hdr, 8, 4)                  # header_version
    struct.pack_into("<I", hdr, 12, page)              # page_size
    struct.pack_into("<I", hdr, 24, len(ramdisk))      # vendor_ramdisk_size
    struct.pack_into("<I", hdr, 2092, header_size)     # header_size
    return bytes(hdr) + ramdisk


def test_android_v2():
    bi = parse_boot_image(_android_v2(b"KERNEL-BYTES", b"RAMDISK-CPIO-BYTES"))
    assert bi is not None and bi.kind == "boot" and bi.header_version == 2
    assert bi.kernel == b"KERNEL-BYTES"
    assert bi.ramdisk == b"RAMDISK-CPIO-BYTES"


def test_android_v3():
    bi = parse_boot_image(_android_v3(b"KDATA" * 1000, b"RDATA" * 500))
    assert bi is not None and bi.header_version == 3
    assert bi.kernel == b"KDATA" * 1000
    assert bi.ramdisk == b"RDATA" * 500


def test_vendor_boot():
    bi = parse_boot_image(_vendor_boot(b"VENDOR-RAMDISK"))
    assert bi is not None and bi.kind == "vendor_boot"
    assert bi.kernel is None
    assert bi.ramdisk == b"VENDOR-RAMDISK"


def test_not_a_boot_image():
    assert parse_boot_image(b"ANDROID?" + b"\x00" * 100) is None
    assert parse_boot_image(b"random bytes") is None
