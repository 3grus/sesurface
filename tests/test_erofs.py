"""Tests for the EROFS reader (walk + xattrs + file bytes).

Built against a real `mkfs.erofs` fixture, so the suite skips cleanly where that tool
is absent. Covers the three things the pipeline relies on: directory walk with
uid/gid/mode, the `security.selinux` label (the locator's exec-type map depends on
it), and file-byte reads for both uncompressed (direct parse) and compressed (via
`fsck.erofs`) data.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(
    not (shutil.which("mkfs.erofs") and shutil.which("dump.erofs")),
    reason="mkfs.erofs/dump.erofs not available")


def _build(tmp_path, compress: bool):
    from sesurface.model.erofs import ErofsReader
    src = tmp_path / "src"
    (src / "bin").mkdir(parents=True)
    (src / "javalib").mkdir()
    # A file big enough to actually compress, so the compressed case hits fsck.erofs.
    (src / "bin" / "foo").write_bytes(b"ABCDEFGH" * 4096)
    (src / "javalib" / "service-x.jar").write_bytes(b"jar-bytes")
    fc = tmp_path / "fc.txt"
    fc.write_text("/bin/foo u:object_r:statsd_exec:s0\n"
                  "/javalib(/.*)? u:object_r:system_file:s0\n")
    img = tmp_path / "test.erofs"
    cmd = ["mkfs.erofs", f"--file-contexts={fc}", str(img), str(src)]
    if compress:
        cmd.insert(1, "-zlz4")
    if subprocess.run(cmd, capture_output=True).returncode != 0:
        pytest.skip("mkfs.erofs failed")
    return ErofsReader(str(img), extract_cache=str(tmp_path / "ex"))


def test_walk_metadata(tmp_path):
    r = _build(tmp_path, compress=False)
    try:
        paths = {p: (u, g, m) for p, u, g, m in r.walk()}
    finally:
        r.close()
    assert "/bin/foo" in paths
    assert "/javalib/service-x.jar" in paths
    import stat
    assert stat.S_ISDIR(paths["/bin"][2])
    assert stat.S_ISREG(paths["/bin/foo"][2])


def test_selinux_label(tmp_path):
    r = _build(tmp_path, compress=False)
    try:
        assert r.selinux_label("/bin/foo") == "statsd_exec"
        assert r.selinux_label("/javalib/service-x.jar") == "system_file"
        assert r.selinux_label("/nope") is None
    finally:
        r.close()


def test_read_uncompressed(tmp_path):
    r = _build(tmp_path, compress=False)
    try:
        assert r.read_bytes("/javalib/service-x.jar") == b"jar-bytes"
        assert r.read_bytes("/bin/foo") == b"ABCDEFGH" * 4096
    finally:
        r.close()


def test_read_compressed_via_fsck(tmp_path):
    if not shutil.which("fsck.erofs"):
        pytest.skip("fsck.erofs not available")
    r = _build(tmp_path, compress=True)
    try:
        # Metadata/xattrs still parse directly; bytes come back via fsck.erofs.
        assert r.selinux_label("/bin/foo") == "statsd_exec"
        assert r.read_bytes("/bin/foo") == b"ABCDEFGH" * 4096
    finally:
        r.close()
