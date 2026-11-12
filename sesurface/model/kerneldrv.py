"""Attribute a device-node ioctl to the kernel driver (and code) behind it.

An ioctl into `/dev/<x>` is a call into kernel code -- the driver's
`unlocked_ioctl` handler -- not a userspace server, so "where is the code?" has a
different answer than for a binder service. Two parts:

  * **Which driver / handler / command set.** A curated map from the SELinux device
    *type* (`ashmem_device`, `binder_device`, ...) to the driver, its ioctl handler
    symbol, the upstream source file, and the `_IOC` command decode for its type byte.
    This is deterministic Linux/Android kernel knowledge, the same spirit as the
    binder ioctl table that already lived in `attribute.py`.

  * **Where that code physically lives on the image.** A driver is either built into
    the kernel image (a `bzImage`/`Image` like `kernel-ranchu`; the device's `/dev`
    node is created at runtime, so there is no on-disk file to open -- the code is in
    the kernel binary, reached by symbol via kallsyms) or shipped as a loadable
    module (`.ko`, which *is* an on-disk ELF with the handler symbol). We index the
    modules and the kernel image so attribution can name the exact file to open, and
    say which case it is.

Nothing here executes the kernel or a module; modules are read with `readelf`.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class DriverInfo:
    """What to open for a device-node ioctl, and its command surface."""
    driver: str                 # human label, e.g. "ashmem"
    handler: str                # kernel ioctl handler symbol, e.g. "ashmem_ioctl"
    source: str                 # upstream source path, e.g. drivers/.../ashmem.c
    type_byte: Optional[int] = None     # the _IOC type byte, if the driver owns one
    commands: dict = field(default_factory=dict)   # {nr: NAME} for that type byte


# _IOC command tables per driver, keyed by the ioctl type byte (the `_IOC_TYPE`).
# nr -> NAME. These let the decoder name each command from (type<<8 | nr).
_ASHMEM_CMDS = {
    1: "ASHMEM_SET_NAME", 2: "ASHMEM_GET_NAME", 3: "ASHMEM_SET_SIZE",
    4: "ASHMEM_GET_SIZE", 5: "ASHMEM_SET_PROT_MASK", 6: "ASHMEM_GET_PROT_MASK",
    7: "ASHMEM_PIN", 8: "ASHMEM_UNPIN", 9: "ASHMEM_GET_PIN_STATUS",
    10: "ASHMEM_PURGE_ALL_CACHES",
}
_BINDER_CMDS = {
    1: "BINDER_WRITE_READ", 3: "BINDER_SET_IDLE_TIMEOUT", 5: "BINDER_SET_MAX_THREADS",
    6: "BINDER_SET_IDLE_PRIORITY", 7: "BINDER_SET_CONTEXT_MGR", 8: "BINDER_THREAD_EXIT",
    9: "BINDER_VERSION", 11: "BINDER_GET_NODE_DEBUG_INFO",
    12: "BINDER_GET_NODE_INFO_FOR_REF", 13: "BINDER_SET_CONTEXT_MGR_EXT",
    14: "BINDER_FREEZE", 15: "BINDER_GET_FROZEN_INFO",
    16: "BINDER_ENABLE_ONEWAY_SPAM_DETECTION",
}
_DMA_HEAP_CMDS = {0: "DMA_HEAP_IOCTL_ALLOC"}
# TTY/termios (type 'T' = 0x54): the common commands SELinux policy allows on ptys/ttys.
_TTY_CMDS = {
    0x01: "TCGETS", 0x02: "TCSETS", 0x03: "TCSETSW", 0x04: "TCSETSF", 0x05: "TCGETA",
    0x09: "TCSBRK", 0x0B: "TCFLSH", 0x10: "TIOCEXCL", 0x11: "TIOCNXCL",
    0x12: "TIOCSCTTY", 0x13: "TIOCGPGRP", 0x14: "TIOCSPGRP", 0x16: "TIOCOUTQ",
    0x1B: "FIONREAD/TIOCINQ", 0x21: "FIONBIO", 0x22: "TIOCSWINSZ", 0x13 + 0x40: "unknown",
}

# SELinux device *type* -> its driver. type_byte/commands are set where the driver
# owns a dedicated _IOC type; otherwise decoding falls back to the shared tables.
DEVICE_DRIVERS: dict[str, DriverInfo] = {
    "ashmem_device": DriverInfo(
        "ashmem", "ashmem_ioctl", "drivers/staging/android/ashmem.c",
        0x77, _ASHMEM_CMDS),
    "ashmem_libcutils_device": DriverInfo(
        "ashmem (libcutils memfd shim)", "ashmem_ioctl",
        "drivers/staging/android/ashmem.c", 0x77, _ASHMEM_CMDS),
    "binder_device": DriverInfo(
        "binder", "binder_ioctl", "drivers/android/binder.c", 0x62, _BINDER_CMDS),
    "hwbinder_device": DriverInfo(
        "binder (hwbinder context)", "binder_ioctl", "drivers/android/binder.c",
        0x62, _BINDER_CMDS),
    "vndbinder_device": DriverInfo(
        "binder (vndbinder context)", "binder_ioctl", "drivers/android/binder.c",
        0x62, _BINDER_CMDS),
    "dmabuf_system_heap_device": DriverInfo(
        "dma-buf system heap", "dma_heap_ioctl", "drivers/dma-buf/dma-heap.c",
        0x48, _DMA_HEAP_CMDS),
    "dmabuf_system_secure_heap_device": DriverInfo(
        "dma-buf system-secure heap", "dma_heap_ioctl", "drivers/dma-buf/dma-heap.c",
        0x48, _DMA_HEAP_CMDS),
    "ion_device": DriverInfo(
        "ION allocator (legacy)", "ion_ioctl", "drivers/staging/android/ion/ion.c"),
    "gpu_device": DriverInfo(
        "GPU (vendor DRM/KMD)", "<drm_ioctl / vendor KMD>", "drivers/gpu/drm/*"),
    "tun_device": DriverInfo(
        "TUN/TAP", "tun_chr_ioctl", "drivers/net/tun.c"),
    "usb_device": DriverInfo(
        "USB devfs", "usbdev_ioctl", "drivers/usb/core/devio.c"),
    "ptmx_device": DriverInfo(
        "pty master", "tty_ioctl", "drivers/tty/tty_io.c", 0x54, _TTY_CMDS),
    "devpts": DriverInfo(
        "pty slave (devpts)", "tty_ioctl", "drivers/tty/pty.c", 0x54, _TTY_CMDS),
    "untrusted_app_all_devpts": DriverInfo(
        "pty slave (devpts)", "tty_ioctl", "drivers/tty/pty.c", 0x54, _TTY_CMDS),
    "owntty_device": DriverInfo(
        "controlling tty", "tty_ioctl", "drivers/tty/tty_io.c", 0x54, _TTY_CMDS),
    "null_device": DriverInfo("mem (null)", "memory_ioctl", "drivers/char/mem.c"),
    "zero_device": DriverInfo("mem (zero)", "memory_ioctl", "drivers/char/mem.c"),
    "random_device": DriverInfo("random", "random_ioctl", "drivers/char/random.c"),
}

# Shared fallback command tables by type byte, for drivers without a dedicated map.
_SHARED_CMDS: dict[int, dict[int, str]] = {0x54: _TTY_CMDS}


def driver_for_type(setype: str) -> Optional[DriverInfo]:
    return DEVICE_DRIVERS.get(setype)


def command_name(cmd: int, drv: Optional[DriverInfo]) -> str:
    """Name one ioctl command (low 16 bits = type<<8 | nr) for a driver, or ''."""
    type_byte = (cmd >> 8) & 0xFF
    nr = cmd & 0xFF
    if drv and drv.type_byte == type_byte and nr in drv.commands:
        return drv.commands[nr]
    shared = _SHARED_CMDS.get(type_byte)
    if shared and nr in shared:
        return shared[nr]
    return ""


# --------------------------------------------------------------------------- #
# Where the driver code lives on the image (kernel binary vs loadable module)
# --------------------------------------------------------------------------- #

@dataclass
class KernelArtifacts:
    """The kernel image and loadable modules present on the image."""
    kernel_image: str = ""       # host path to the kernel binary (bzImage/Image), if found
    kernel_version: str = ""     # version banner parsed from it
    modules: list[str] = field(default_factory=list)   # on-device .ko paths
    # symbol -> .ko device path, filled lazily (readelf per module) on first query.
    _sym_cache: dict = field(default_factory=dict)
    _scanned: bool = False

    def locate_handler(self, handler: str, files=None) -> tuple[str, str]:
        """Return (artifact, note) naming where `handler` lives.

        Prefers a loadable module that defines the symbol; otherwise the driver is
        built into the kernel image (the common case for core drivers), where the
        handler is reachable by symbol via kallsyms. `files` (an ImageFiles) enables
        the module scan; without it we answer from the kernel image alone.
        """
        sym = handler.strip("<>")
        if files is not None and self.modules:
            ko = self._module_for_symbol(sym, files)
            if ko:
                return ko, (f"shipped as a loadable kernel module; `{sym}` is defined "
                            f"in {ko} (open it in Ghidra).")
        if self.kernel_image:
            ver = f" ({self.kernel_version})" if self.kernel_version else ""
            return self.kernel_image, (
                f"built into the kernel image{ver}; there is no /dev file to open -- the "
                f"handler `{sym}` lives in the kernel binary, reached by symbol "
                "(kallsyms) in a Ghidra/vmlinux pass. No loadable module provides it.")
        return "", (f"handler `{sym}` is in the kernel; no kernel image or module was "
                    "located on this image to point at.")

    def _module_for_symbol(self, sym: str, files) -> str:
        if sym in self._sym_cache:
            return self._sym_cache[sym]
        # Scan modules lazily, caching every defined symbol we see along the way.
        import tempfile
        scratch = tempfile.mkdtemp(prefix="sesurface-ko-")
        dst = os.path.join(scratch, "m.ko")
        found = ""
        try:
            for ko in self.modules:
                if not files.extract_to(ko, dst):
                    continue
                for s in _defined_symbols(dst):
                    self._sym_cache.setdefault(s, ko)
                if sym in self._sym_cache:
                    found = self._sym_cache[sym]
                    break
        finally:
            try:
                os.remove(dst)
                os.rmdir(scratch)
            except OSError:
                pass
        self._sym_cache.setdefault(sym, found)
        return found


def _defined_symbols(ko_host: str) -> list[str]:
    """Defined (non-UND) symbol names from a .ko ELF, via readelf."""
    try:
        out = subprocess.run(["readelf", "-sW", ko_host], capture_output=True,
                             text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    syms = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].rstrip(":").isdigit() and parts[6] != "UND":
            nm = parts[7].split("@")[0]
            if nm and nm != "Name":
                syms.append(nm)
    return syms


_KVER_RE = re.compile(rb"(\d+\.\d+\.\d+[-\w.]*-android[-\w.]*)")


def build_kernel_artifacts(image_dir: str, inodes, work_dir: Optional[str] = None) -> KernelArtifacts:
    """Find the kernel image + loadable modules for an unpacked image.

    Prefers a standalone `kernel*`/`Image` file; otherwise unpacks `boot.img` (the
    kernel lives inside the Android boot container) into `work_dir` and uses that.
    """
    ka = KernelArtifacts()
    try:
        names = os.listdir(image_dir)
    except OSError:
        names = []
    path = None
    standalone = [n for n in names if n.startswith("kernel")] or \
        [n for n in names if n in ("Image", "Image.gz", "Image.lz4", "vmlinux")]
    if standalone:
        path = os.path.join(image_dir, sorted(standalone)[0])
    elif "boot.img" in names and work_dir:
        path = _kernel_from_boot(os.path.join(image_dir, "boot.img"), work_dir)
    if path and os.path.exists(path):
        ka.kernel_image = path
        try:
            with open(path, "rb") as f:
                head = f.read(4 * 1024 * 1024)
            m = _KVER_RE.search(head)
            if m:
                ka.kernel_version = m.group(1).decode("latin1")
        except OSError:
            pass
    ka.modules = sorted(p for p, meta in inodes.meta.items()
                        if p.endswith(".ko") and not meta.is_dir)
    return ka


def _kernel_from_boot(boot_path: str, work_dir: str) -> Optional[str]:
    """Extract the kernel from a boot.img into `work_dir` (cached); return its path."""
    from .bootimg import parse_boot_image
    out = os.path.join(work_dir, "kernel-from-boot.bin")
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return out
    try:
        with open(boot_path, "rb") as f:
            bi = parse_boot_image(f.read())
    except OSError:
        return None
    if bi is None or not bi.kernel:
        return None
    os.makedirs(work_dir, exist_ok=True)
    with open(out, "wb") as f:
        f.write(bi.kernel)
    return out
