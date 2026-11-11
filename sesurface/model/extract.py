"""Read individual files out of the carved partitions, by on-device path.

Many stages need the *contents* of specific files -- the policy, the context files,
build.props, APK manifests -- addressed by their on-device path (`/vendor/etc/...`).
This module maps a device path to the partition that holds it and reads it with
`debugfs` (ext4). It keeps one long-lived `debugfs` process per partition, so
reading dozens of config files costs almost nothing.

This complements `inode.py`: that builds the whole metadata index; this reads the
bytes of particular files on demand.
"""

from __future__ import annotations

from typing import Optional

from .inode import Ext4Reader
from .partitions import Partition, PartitionSet


class ImageFiles:
    """On-demand file reads from an unpacked image, addressed by device path."""

    def __init__(self, ps: PartitionSet):
        self._ps = ps
        self._readers: dict[str, object] = {}
        # Non-system mountpoints, longest first, so /vendor beats / for /vendor/*.
        self._mounts = sorted(
            (p for p in ps.partitions.values() if p.name != "system"),
            key=lambda p: len(p.mountpoint), reverse=True)
        self._system = ps.partitions.get("system")

    def resolve(self, device_path: str) -> Optional[tuple[Partition, str]]:
        """Find (partition, in-partition path) for an on-device path.

        A non-system partition wins when its mountpoint is a path-prefix of the
        device path (e.g. `/vendor/...` -> the vendor partition, path `/...`).
        Everything else falls to the system partition, which is system-as-root so
        its in-partition path equals the device path.
        """
        for p in self._mounts:
            mp = p.mountpoint.rstrip("/")
            if device_path == mp or device_path.startswith(mp + "/"):
                inner = device_path[len(mp):] or "/"
                return (p, inner)
        if self._system is not None:
            return (self._system, device_path)
        return None

    def _reader(self, part: Partition):
        """A persistent reader for a partition (Ext4Reader or ErofsReader), or None."""
        if part.fstype not in ("ext4", "erofs"):
            return None                     # cpio ramdisk etc.: not block-readable here
        r = self._readers.get(part.name)
        if r is None:
            if part.fstype == "ext4":
                r = Ext4Reader(part.image)
            else:
                from .erofs import ErofsReader
                r = ErofsReader(part.image)
            self._readers[part.name] = r
        return r

    def read_bytes(self, device_path: str) -> Optional[bytes]:
        """Return the file's contents, or None if it is absent/unreadable."""
        hit = self.resolve(device_path)
        if not hit:
            return None
        part, inner = hit
        r = self._reader(part)
        if r is None:
            return None
        if isinstance(r, Ext4Reader):
            return _dump_via_debugfs(r, inner)
        return r.read_bytes(inner)          # ErofsReader

    def read_text(self, device_path: str) -> Optional[str]:
        b = self.read_bytes(device_path)
        return b.decode("utf-8", "replace") if b is not None else None

    def exists(self, device_path: str) -> bool:
        hit = self.resolve(device_path)
        if not hit:
            return False
        part, inner = hit
        r = self._reader(part)
        if r is None:
            return False
        if not isinstance(r, Ext4Reader):
            return r.read_bytes(inner) is not None    # ErofsReader
        out = r._cmd(f'stat "{inner}"')     # Non-empty, non-error output => exists.
        return any("Inode:" in line for line in out)

    def extract_to(self, device_path: str, dest_path: str) -> bool:
        """Write the file's contents to a host path (for tools that need a real file)."""
        hit = self.resolve(device_path)
        if not hit:
            return False
        part, inner = hit
        r = self._reader(part)
        if r is None:
            return False
        import os
        if not isinstance(r, Ext4Reader):
            return r.extract(inner, dest_path)          # ErofsReader
        # debugfs `dump` writes directly to a host file from the live process.
        r._cmd(f'dump "{inner}" "{dest_path}"')
        return os.path.exists(dest_path) and os.path.getsize(dest_path) > 0

    def close(self) -> None:
        for r in self._readers.values():
            r.close()
        self._readers.clear()


def _dump_via_debugfs(reader: Ext4Reader, inner: str) -> Optional[bytes]:
    """Read a file's bytes by dumping it to a temp file (debugfs has no pipe-out)."""
    import os
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix="sesurface-")
    os.close(fd)
    try:
        reader._cmd(f'dump "{inner}" "{tmp}"')
        if os.path.getsize(tmp) == 0:
            # Could be a genuinely empty file or a missing one; treat as empty bytes
            # only if the node exists, else None.
            st = reader._cmd(f'stat "{inner}"')
            if not any("Inode:" in line for line in st):
                return None
        with open(tmp, "rb") as f:
            return f.read()
    finally:
        os.unlink(tmp)
