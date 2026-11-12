"""Unpack an Android boot image into its kernel and ramdisk.

On a device image the kernel and the first-stage ramdisk are not standalone files --
they live inside `boot.img` (and, on newer layouts, `init_boot.img` for the generic
ramdisk and `vendor_boot.img` for the vendor ramdisk). Those are *container* images,
not filesystems, so we expand them into their constituents, which then flow into the
existing readers: the kernel to the kallsyms enrichment, the ramdisk cpio to
`ramdisk.py`. No filesystem tree is extracted, so nothing here affects DAC.

Supports the `ANDROID!` boot header v0-v4 and the `VNDRBOOT` vendor-boot header v3/v4.
A field we cannot make sense of yields an empty result rather than a wrong extraction.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

_BOOT_MAGIC = b"ANDROID!"
_VENDOR_MAGIC = b"VNDRBOOT"


@dataclass
class BootImage:
    kind: str                       # "boot" | "vendor_boot"
    header_version: int
    kernel: Optional[bytes] = None
    ramdisk: Optional[bytes] = None


def _round_up(n: int, align: int) -> int:
    return (n + align - 1) // align * align if align else n


def parse_boot_image(data: bytes) -> Optional[BootImage]:
    """Parse a boot/vendor_boot image, returning its kernel and/or ramdisk blobs."""
    if data[:8] == _BOOT_MAGIC:
        return _parse_android(data)
    if data[:8] == _VENDOR_MAGIC:
        return _parse_vendor(data)
    return None


def _parse_android(data: bytes) -> Optional[BootImage]:
    try:
        header_version = struct.unpack_from("<I", data, 40)[0]
    except struct.error:
        return None
    if header_version >= 3:
        # v3/v4: fixed 4096-byte pages; header is kernel_size, ramdisk_size, ...
        kernel_size, ramdisk_size = struct.unpack_from("<II", data, 8)
        page = 4096
        koff = page
        roff = koff + _round_up(kernel_size, page)
    else:
        # v0-v2: page_size is a field; kernel at page 1, ramdisk after it.
        kernel_size, _ka, ramdisk_size, _ra, _ss, _sa, _ta, page = \
            struct.unpack_from("<IIIIIIII", data, 8)
        if page <= 0:
            return None
        koff = page
        roff = koff + _round_up(kernel_size, page)
    kernel = data[koff:koff + kernel_size] if kernel_size else None
    ramdisk = data[roff:roff + ramdisk_size] if ramdisk_size else None
    return BootImage("boot", header_version, kernel, ramdisk)


def _parse_vendor(data: bytes) -> Optional[BootImage]:
    try:
        header_version, page = struct.unpack_from("<II", data, 8)
        vendor_ramdisk_size = struct.unpack_from("<I", data, 24)[0]
        header_size = struct.unpack_from("<I", data, 2092)[0]
    except struct.error:
        return None
    if page <= 0:
        return None
    roff = _round_up(header_size, page)
    ramdisk = data[roff:roff + vendor_ramdisk_size] if vendor_ramdisk_size else None
    return BootImage("vendor_boot", header_version, None, ramdisk)
