"""Tests for the APEX reader and the manifest/mount-point mapping.

Image-independent: the APEX manifest parse and the container-unwrap logic are tested
with hand-built bytes and a tiny zip; the end-to-end "payload mounts at
/apex/<package>" wiring is covered where `mke2fs` is available (a 1 MiB ext4 payload),
and skipped cleanly otherwise so the suite stays runnable without that tool.
"""

from __future__ import annotations

import io
import os
import shutil
import struct
import subprocess
import tempfile
import zipfile

import pytest

from sesurface.model.apex import (_payload_from_zip, index_apex_partitions,
                                  parse_apex_manifest)
from sesurface.model.inode import InodeIndex
from sesurface.model.partitions import PartitionSet


def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            break
    return bytes(out)


def _manifest(name: str, version: int = 330000000) -> bytes:
    """A minimal ApexManifest protobuf: field 1 (name), field 2 (version)."""
    nb = name.encode()
    return (b"\x0a" + _varint(len(nb)) + nb          # field 1, length-delimited
            + b"\x10" + _varint(version))            # field 2, varint


def test_parse_manifest_name():
    assert parse_apex_manifest(_manifest("com.android.os.statsd")) == "com.android.os.statsd"
    assert parse_apex_manifest(_manifest("com.android.adbd")) == "com.android.adbd"


def test_parse_manifest_long_name():
    # A name >127 bytes exercises the multi-byte varint length.
    long = "com.android." + "x" * 200
    assert parse_apex_manifest(_manifest(long)) == long


def test_parse_manifest_rejects_garbage():
    assert parse_apex_manifest(b"") is None
    assert parse_apex_manifest(b"\x12\x05hello") is None   # field 2, not field 1


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_payload_from_apex_zip():
    """A plain .apex: payload + manifest extracted, package read."""
    with tempfile.TemporaryDirectory() as d:
        container = os.path.join(d, "x.apex")
        with open(container, "wb") as f:
            f.write(_zip_bytes({
                "apex_payload.img": b"PAYLOAD-BYTES",
                "apex_manifest.pb": _manifest("com.android.foo"),
            }))
        with zipfile.ZipFile(container) as z:
            got = _payload_from_zip(z, d)
        assert got is not None
        pkg, payload = got
        assert pkg == "com.android.foo"
        assert open(payload, "rb").read() == b"PAYLOAD-BYTES"


def test_payload_from_capex_zip():
    """A .capex wraps the real .apex as `original_apex`; unwrap one level."""
    inner = _zip_bytes({
        "apex_payload.img": b"INNER-PAYLOAD",
        "apex_manifest.pb": _manifest("com.android.bar"),
    })
    with tempfile.TemporaryDirectory() as d:
        container = os.path.join(d, "x.capex")
        with open(container, "wb") as f:
            f.write(_zip_bytes({
                "original_apex": inner,
                "apex_manifest.pb": _manifest("com.android.bar"),
            }))
        with zipfile.ZipFile(container) as z:
            got = _payload_from_zip(z, d)
        assert got is not None
        pkg, payload = got
        assert pkg == "com.android.bar"
        assert open(payload, "rb").read() == b"INNER-PAYLOAD"


def test_payload_missing_returns_none():
    with tempfile.TemporaryDirectory() as d:
        with zipfile.ZipFile(os.path.join(d, "x.apex"), "w") as z:
            z.writestr("AndroidManifest.xml", "x")
        with zipfile.ZipFile(os.path.join(d, "x.apex")) as z:
            assert _payload_from_zip(z, d) is None


class _FakeFiles:
    """Stand-in for ImageFiles: extract_to copies from a prepared map."""

    def __init__(self, blobs: dict[str, bytes]):
        self._blobs = blobs

    def extract_to(self, device_path: str, dest_path: str) -> bool:
        if device_path not in self._blobs:
            return False
        with open(dest_path, "wb") as f:
            f.write(self._blobs[device_path])
        return True


def _make_ext4(path: str, tree: dict[str, bytes]) -> bool:
    """Build a tiny ext4 image containing `tree` (path->bytes), or False if no tool."""
    if not (shutil.which("mke2fs") and shutil.which("e2cp")):
        return False
    with open(path, "wb") as f:
        f.truncate(1 << 20)
    if subprocess.run(["mke2fs", "-F", "-q", "-t", "ext4", path],
                      capture_output=True).returncode != 0:
        return False
    return True


def test_index_apex_mounts_payload_ext4():
    """End-to-end: a container's ext4 payload mounts at /apex/<package> and indexes.

    Requires `mke2fs`+`debugfs` (debugfs is a hard dep of the tool). Skips if the
    payload could not be built.
    """
    if not shutil.which("debugfs") or not shutil.which("mke2fs"):
        pytest.skip("debugfs/mke2fs not available")
    with tempfile.TemporaryDirectory() as d:
        payload = os.path.join(d, "payload.img")
        with open(payload, "wb") as f:
            f.truncate(1 << 20)
        if subprocess.run(["mke2fs", "-F", "-q", "-t", "ext4", "-d",
                           _seed_dir(d), payload], capture_output=True).returncode != 0:
            pytest.skip("mke2fs -d not supported")
        container = os.path.join(d, "com.android.test.apex")
        with open(container, "wb") as f:
            f.write(_zip_bytes({
                "apex_payload.img": open(payload, "rb").read(),
                "apex_manifest.pb": _manifest("com.android.test"),
            }))
        files = _FakeFiles({"/system/apex/com.android.test.apex":
                            open(container, "rb").read()})
        ps = PartitionSet()
        idx = InodeIndex()
        idx.meta["/system/apex/com.android.test.apex"] = _reg_meta()
        work = os.path.join(d, "work")
        os.makedirs(work)
        notes = index_apex_partitions(ps, files, idx, work, read_labels=False)
        assert "apex:com.android.test" in ps.partitions
        part = ps.partitions["apex:com.android.test"]
        assert part.mountpoint == "/apex/com.android.test"
        assert part.fstype == "ext4"
        # The seeded file is indexed under the runtime mount path.
        assert "/apex/com.android.test/bin/hello" in idx.meta
        assert any("mounted 1" in n for n in notes)


def _seed_dir(base: str) -> str:
    seed = os.path.join(base, "seed")
    os.makedirs(os.path.join(seed, "bin"), exist_ok=True)
    with open(os.path.join(seed, "bin", "hello"), "wb") as f:
        f.write(b"\x7fELF-ish")
    return seed


def _reg_meta():
    from sesurface.model.inode import InodeMeta
    return InodeMeta(uid=0, gid=0, mode=0o100644, setype=None, caps=None)
