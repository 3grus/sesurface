"""Tests for kernel-driver ioctl attribution (driver map, command decode, location)."""

from __future__ import annotations

import struct

from sesurface.model.kerneldrv import (KernelArtifacts, build_kernel_artifacts,
                                       command_name, driver_for_type)


def test_driver_map():
    d = driver_for_type("ashmem_device")
    assert d is not None
    assert d.handler == "ashmem_ioctl"
    assert "ashmem.c" in d.source
    assert driver_for_type("binder_device").handler == "binder_ioctl"
    assert driver_for_type("not_a_device") is None


def test_command_decode():
    ashmem = driver_for_type("ashmem_device")
    # type byte 0x77 ('w'), nr 3 -> ASHMEM_SET_SIZE
    assert command_name((0x77 << 8) | 3, ashmem) == "ASHMEM_SET_SIZE"
    binder = driver_for_type("binder_device")
    assert command_name(0x6201, binder) == "BINDER_WRITE_READ"
    # Unknown command for the driver -> empty (caller shows the raw number).
    assert command_name(0x9999, ashmem) == ""


def test_shared_tty_table():
    # A tty driver decodes termios commands from the shared type-0x54 table.
    ptmx = driver_for_type("ptmx_device")
    assert command_name(0x5401, ptmx) == "TCGETS"


def test_locate_handler_builtin():
    """With a kernel image and no modules, the handler is 'built into the kernel'."""
    ka = KernelArtifacts(kernel_image="/img/kernel-ranchu",
                         kernel_version="5.15.41-android13", modules=[])
    art, note = ka.locate_handler("ashmem_ioctl", files=None)
    assert art == "/img/kernel-ranchu"
    assert "built into the kernel image" in note
    assert "5.15.41-android13" in note


def test_build_kernel_artifacts(tmp_path):
    """The kernel image is found and its version banner parsed."""
    # A stand-in "kernel" file carrying an android version string.
    kimg = tmp_path / "kernel-ranchu"
    kimg.write_bytes(b"\x00" * 4096 + b"Linux version 5.15.41-android13-8-00055-gabc "
                     + b"junk")

    class _Inodes:
        meta = {}

    ka = build_kernel_artifacts(str(tmp_path), _Inodes())
    assert ka.kernel_image.endswith("kernel-ranchu")
    assert ka.kernel_version.startswith("5.15.41-android13")
    assert ka.modules == []
