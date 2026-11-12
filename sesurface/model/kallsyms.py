"""Optional kernel-symbol enrichment: confirm a driver handler against the kernel.

This is **enrichment, never a dependency.** The curated driver map (`kerneldrv.py`)
already names a device's ioctl handler (`ashmem_ioctl`, ...) and where it lives. When
the kernel binary is present and decompressible, this module upgrades that from
*map-asserted* to *confirmed in this kernel*, and -- if the mature external symbolizer
`vmlinux-to-elf` is installed -- to a verified address. Every step degrades cleanly:
a kernel that will not decompress, has no kallsyms, or is missing the tool simply
leaves the map result as-is, clearly labelled.

Two tiers:
  * **Presence (zero-dependency).** Decompress the kernel image to the raw `vmlinux`
    and check whether the handler's name occurs as a bounded token. On Android kernels
    the names are available as literal strings (BTF with `CONFIG_DEBUG_INFO_BTF`,
    ftrace tables, `__ksymtab_strings`), even for static functions, so a bounded scan
    reliably answers "is `ashmem_ioctl` in THIS kernel?" without parsing kallsyms.
  * **Address (optional).** If `vmlinux-to-elf` is on PATH it is run once to rebuild a
    symbolised ELF, from which the exact address is read. This is the proper kallsyms
    parse; we defer to that well-tested tool rather than reimplement it fragilely.

Kernel images ship compressed inside a `bzImage`/`Image` (gzip, xz, lzma, bzip2, lz4,
or zstd). `extract_vmlinux` finds the real compressed stream by trying each known magic
and keeping the output that decompresses and contains the kernel banner.
"""

from __future__ import annotations

import os
import re
import struct
import subprocess
from typing import Optional

_BANNER = b"Linux version"


# --------------------------------------------------------------------------- #
# Decompression (extract-vmlinux, in Python)
# --------------------------------------------------------------------------- #

def _try_gzip(buf: bytes) -> Optional[bytes]:
    import zlib
    try:
        return zlib.decompressobj(31).decompress(buf)
    except Exception:
        return None


def _try_xz(buf: bytes) -> Optional[bytes]:
    import lzma
    try:
        return lzma.decompress(buf, format=lzma.FORMAT_XZ)
    except Exception:
        # A trailing-garbage stream: decompress what forms a valid stream.
        try:
            d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            return d.decompress(buf)
        except Exception:
            return None


def _try_lzma(buf: bytes) -> Optional[bytes]:
    import lzma
    try:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        return d.decompress(buf)
    except Exception:
        return None


def _try_bzip2(buf: bytes) -> Optional[bytes]:
    import bz2
    try:
        return bz2.BZ2Decompressor().decompress(buf)
    except Exception:
        return None


def _try_lz4_legacy(buf: bytes) -> Optional[bytes]:
    try:
        import lz4.block  # type: ignore
    except ImportError:
        return None
    out = bytearray()
    off = 4                       # skip the 4-byte legacy magic
    try:
        while off + 4 <= len(buf):
            bs, = struct.unpack_from("<I", buf, off)
            off += 4
            if bs == 0 or bs == 0x184C2102 or off + bs > len(buf):
                break
            out += lz4.block.decompress(buf[off:off + bs],
                                        uncompressed_size=16 * 1024 * 1024)
            off += bs
    except Exception:
        return bytes(out) if out else None
    return bytes(out) or None


def _try_zstd(buf: bytes) -> Optional[bytes]:
    try:
        import zstandard  # type: ignore
        return zstandard.ZstdDecompressor().decompressobj().decompress(buf)
    except Exception:
        pass
    try:
        import zstd  # type: ignore
        return zstd.decompress(buf)
    except Exception:
        return None


# (name, magic bytes, decompressor). Order roughly by how common they are on Android.
_FORMATS = [
    ("lz4", b"\x02\x21\x4c\x18", _try_lz4_legacy),
    ("gzip", b"\x1f\x8b\x08", _try_gzip),
    ("xz", b"\xfd7zXZ\x00", _try_xz),
    ("zstd", b"\x28\xb5\x2f\xfd", _try_zstd),
    ("bzip2", b"BZh", _try_bzip2),
    ("lzma", b"\x5d\x00\x00", _try_lzma),
]


def decompress_kernel(data: bytes) -> tuple[Optional[bytes], str]:
    """Return (vmlinux bytes, format name) from a kernel image, or (None, "")."""
    # An already-raw/ELF kernel (uncompressed Image) that carries the banner.
    if _BANNER in data[:8 * 1024 * 1024] and data[:4] == b"\x7fELF":
        return data, "elf"
    for name, magic, fn in _FORMATS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            out = fn(data[i:])
            if out and _BANNER in out:
                return out, name
            start = i + 1
    return None, ""


def extract_vmlinux(kernel_path: str, cache_dir: str) -> tuple[Optional[str], str]:
    """Decompress a kernel image to `<cache>/vmlinux.bin` (cached). (path, format)."""
    os.makedirs(cache_dir, exist_ok=True)
    out_path = os.path.join(cache_dir, "vmlinux.bin")
    meta_path = out_path + ".fmt"
    if os.path.exists(out_path) and os.path.exists(meta_path):
        with open(meta_path) as f:
            return out_path, f.read().strip()
    try:
        with open(kernel_path, "rb") as f:
            data = f.read()
    except OSError:
        return None, ""
    vm, fmt = decompress_kernel(data)
    if vm is None:
        return None, ""
    with open(out_path, "wb") as f:
        f.write(vm)
    with open(meta_path, "w") as f:
        f.write(fmt)
    return out_path, fmt


# --------------------------------------------------------------------------- #
# Symbol presence / address
# --------------------------------------------------------------------------- #

class KernelSymbols:
    """Lazy symbol lookups over a decompressed kernel. All methods degrade to None."""

    def __init__(self, kernel_path: str, cache_dir: str):
        self._kernel_path = kernel_path
        self._cache_dir = cache_dir
        self._vmlinux: Optional[str] = None
        self._fmt = ""
        self._data: Optional[bytes] = None
        self._tried = False
        self._present: dict[str, bool] = {}
        self._addr: dict[str, Optional[int]] = {}
        self._elf: Optional[str] = None
        self._elf_tried = False

    @property
    def format(self) -> str:
        self._ensure()
        return self._fmt

    def available(self) -> bool:
        """True if the kernel decompressed and can be scanned."""
        self._ensure()
        return self._data is not None

    def _ensure(self) -> None:
        if self._tried:
            return
        self._tried = True
        if not self._kernel_path or not os.path.exists(self._kernel_path):
            return
        self._vmlinux, self._fmt = extract_vmlinux(self._kernel_path, self._cache_dir)
        if self._vmlinux:
            try:
                with open(self._vmlinux, "rb") as f:
                    self._data = f.read()
            except OSError:
                self._data = None

    @staticmethod
    def _bounded(name: str) -> re.Pattern:
        # The symbol as a whole token: not flanked by identifier characters, so
        # `ashmem_ioctl` does not match inside `my_ashmem_ioctl_wrapper`.
        return re.compile(rb"(?<![A-Za-z0-9_])" + re.escape(name.encode())
                          + rb"(?![A-Za-z0-9_])")

    def present(self, name: str) -> bool:
        """Whether `name` occurs as a bounded symbol token in this kernel."""
        name = name.strip("<>").strip()
        if not name or name in ("drm_ioctl / vendor KMD",):
            return False
        if name in self._present:
            return self._present[name]
        self._ensure()
        ok = bool(self._data and self._bounded(name).search(self._data))
        self._present[name] = ok
        return ok

    def address(self, name: str) -> Optional[int]:
        """Verified address via `vmlinux-to-elf` if installed, else None."""
        name = name.strip("<>").strip()
        if not name:
            return None
        if name in self._addr:
            return self._addr[name]
        addr = self._lookup_address(name)
        self._addr[name] = addr
        return addr

    def _elf_path(self) -> Optional[str]:
        if self._elf_tried:
            return self._elf
        self._elf_tried = True
        self._ensure()
        if not self._vmlinux:
            return None
        import shutil
        tool = shutil.which("vmlinux-to-elf")
        if not tool:
            return None
        out = os.path.join(self._cache_dir, "vmlinux.elf")
        if not os.path.exists(out):
            try:
                subprocess.run([tool, self._kernel_path, out],
                               capture_output=True, timeout=600)
            except (OSError, subprocess.SubprocessError):
                return None
        self._elf = out if os.path.exists(out) else None
        return self._elf

    def _lookup_address(self, name: str) -> Optional[int]:
        elf = self._elf_path()
        if not elf:
            return None
        try:
            out = subprocess.run(["readelf", "-sW", elf], capture_output=True,
                                 text=True, timeout=60).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[7].split("@")[0] == name:
                try:
                    return int(parts[1], 16)
                except ValueError:
                    continue
        return None
