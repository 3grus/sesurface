"""Tests for VINTF manifest parsing and passthrough .so resolution."""

from __future__ import annotations

from sesurface.model.vintf import impl_so_for, parse_vintf


class _FakeFiles:
    def __init__(self, data):
        self._data = data

    def read_text(self, path):
        return self._data.get(path)


class _FakeInodes:
    def __init__(self, paths):
        self.meta = {p: object() for p in paths}


_MANIFEST = """<?xml version="1.0"?>
<manifest version="5.0" type="device">
    <hal format="hidl">
        <name>android.hardware.graphics.mapper</name>
        <transport arch="32+64">passthrough</transport>
        <version>3.0</version>
        <interface>
            <name>IMapper</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.camera.provider</name>
        <transport>hwbinder</transport>
        <version>2.4</version>
        <interface>
            <name>ICameraProvider</name>
            <instance>legacy/0</instance>
        </interface>
    </hal>
</manifest>
"""

# A compatibility matrix has the same <hal> shape but is a REQUIREMENT, not a
# provided implementation. It must be ignored so it cannot shadow the manifest.
_MATRIX = """<?xml version="1.0"?>
<compatibility-matrix version="1.0" type="framework">
    <hal format="hidl" optional="true">
        <name>android.hardware.graphics.mapper</name>
        <version>2.0-1</version>
        <interface>
            <name>IMapper</name>
            <instance>default</instance>
        </interface>
    </hal>
</compatibility-matrix>
"""


def _db():
    files = _FakeFiles({
        "/vendor/etc/vintf/manifest.xml": _MANIFEST,
        "/system/etc/vintf/compatibility_matrix.xml": _MATRIX,
    })
    inodes = _FakeInodes([
        "/vendor/etc/vintf/manifest.xml",
        "/system/etc/vintf/compatibility_matrix.xml",
    ])
    return parse_vintf(files, inodes)


def test_parses_manifest_hals_and_transport():
    db = _db()
    mapper = db.hal_for_iface("android.hardware.graphics.mapper::IMapper")
    assert mapper is not None
    assert mapper.is_passthrough and mapper.versions == ["3.0"]
    cam = db.hal_for_iface("android.hardware.camera.provider::ICameraProvider")
    assert cam is not None and cam.transport == "hwbinder" and not cam.is_passthrough


def test_compatibility_matrix_is_ignored():
    db = _db()
    # Only the manifest file should have contributed; the matrix must not shadow the
    # real passthrough entry with its version-range requirement.
    assert "/system/etc/vintf/compatibility_matrix.xml" not in db.files_read
    mapper = db.hal_for_iface("android.hardware.graphics.mapper::IMapper")
    assert mapper.is_passthrough   # not overwritten by the matrix's "2.0-1" entry.


def test_impl_so_resolution():
    db = _db()
    mapper = db.hal_for_iface("android.hardware.graphics.mapper::IMapper")
    inodes = _FakeInodes([
        "/vendor/lib64/hw/android.hardware.graphics.mapper@3.0-impl-ranchu.so",
        "/vendor/lib64/hw/unrelated.so",
        "/vendor/bin/hw/android.hardware.camera.provider@2.4-service",
    ])
    sos = impl_so_for(mapper, inodes)
    assert sos == ["/vendor/lib64/hw/android.hardware.graphics.mapper@3.0-impl-ranchu.so"]
