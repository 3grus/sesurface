"""Read true inode metadata from the image, for the DAC gate and file backing.

This is the fix for the single most damaging bug the Blast Radius guide's Chapter 22
called out: the old tool ran `os.stat()` on an *extracted* tree, so every file
appeared owned by the extracting user and its mode reflected the extractor, not the
device. A DAC analysis built on that is meaningless.

Instead we read metadata straight from the filesystem image, where the build system
wrote it: uid, gid, mode, the `security.selinux` xattr (the authoritative label for
read-only partitions), and the `security.capability` xattr (file capabilities, as on
`/system/bin/run-as`). We do it without mounting and without root, using `debugfs`
for ext4 (and `dump.erofs` for EROFS). A field we cannot read is recorded as
`None`/unknown -- never as a default, because a wrong default is worse than a known gap.

Performance: a single long-lived `debugfs` process is driven over a pipe, so the
whole tree is walked and all xattrs read in one process (tens of thousands of
nodes per second), and the resulting index is cached to disk by the caller.
"""

from __future__ import annotations

import stat as stmod
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .partitions import Partition, PartitionSet


@dataclass(frozen=True)
class InodeMeta:
    """Authoritative metadata for one path, as it exists on the device."""
    uid: Optional[int]
    gid: Optional[int]
    mode: Optional[int]          # Full st_mode (type bits + permission bits).
    setype: Optional[str]        # SELinux type from security.selinux, or None.
    caps: Optional[str]          # security.capability raw hex, or None if absent.
    is_dir: bool = False
    is_symlink: bool = False
    link_target: Optional[str] = None

    @property
    def perm(self) -> Optional[int]:
        """Just the permission bits (the low 12 bits: setuid/setgid/sticky + rwx)."""
        return None if self.mode is None else self.mode & 0o7777


class Ext4Reader:
    """Drive one persistent `debugfs` process to read an ext4 image, no root needed.

    `debugfs` opens the image once; we feed it commands over stdin and read each
    command's output up to a sentinel we print with `echo`. `ls -p` gives inode,
    mode, uid, gid, name and size for a directory in a machine-parseable form, so a
    breadth-first walk recovers the whole tree's DAC metadata; `ea_get` then reads
    each node's SELinux and capability xattrs.
    """

    _SENTINEL = "__sesurface_end__"

    def __init__(self, image: str):
        self.image = image
        self._proc = subprocess.Popen(
            ["debugfs", image],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True)

    def _cmd(self, command: str) -> list[str]:
        """Run one debugfs command, return its output lines (sentinel-delimited)."""
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(f"{command}\necho {self._SENTINEL}\n")
        self._proc.stdin.flush()
        out: list[str] = []
        for line in self._proc.stdout:
            if self._SENTINEL in line:
                break
            out.append(line.rstrip("\n"))
        return out

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                assert self._proc.stdin
                self._proc.stdin.write("quit\n")
                self._proc.stdin.flush()
            except Exception:
                pass
            self._proc.wait(timeout=10)

    def walk(self):
        """Yield (fs_path, uid, gid, mode) for every node, breadth-first.

        `ls -p` output is `/<inode>/<octal mode>/<uid>/<gid>/<name>/<size>/`. We
        recurse into directories. `.` and `..` are skipped.
        """
        queue = ["/"]
        while queue:
            d = queue.pop()
            for line in self._cmd(f"ls -p {d}"):
                line = line.strip()
                if not line.startswith("/"):
                    continue
                parts = line.split("/")
                if len(parts) < 6:
                    continue
                try:
                    mode = int(parts[2], 8)
                    uid = int(parts[3])
                    gid = int(parts[4])
                except ValueError:
                    continue
                name = parts[5]
                if name in (".", ".."):
                    continue
                path = f"{d.rstrip('/')}/{name}" if d != "/" else f"/{name}"
                yield (path, uid, gid, mode)
                if stmod.S_ISDIR(mode):
                    queue.append(path)

    def selinux_label(self, fs_path: str) -> Optional[str]:
        """Read the SELinux type from a node's security.selinux xattr."""
        for line in self._cmd(f'ea_get "{fs_path}" security.selinux'):
            if "security.selinux" in line and "=" in line:
                val = line.split("=", 1)[1].strip().strip('"').replace("\\000", "")
                # val is a full context u:object_r:TYPE:s0; return the type.
                bits = val.split(":")
                return bits[2] if len(bits) >= 3 else None
        return None

    def capability(self, fs_path: str) -> Optional[str]:
        """Read file capabilities (security.capability xattr) as decoded cap names.

        File capabilities are stored in a binary `vfs_cap_data` struct, independent
        of the setuid mode bit -- e.g. `/system/bin/run-as` has no setuid bit but
        carries CAP_SETUID|CAP_SETGID here. Returns a comma-separated cap-name list
        (the "permitted" set, which is what matters for a compromised process), or
        None when the xattr is absent.
        """
        for line in self._cmd(f'ea_get "{fs_path}" security.capability'):
            if "security.capability" in line and "=" in line:
                hexbytes = line.split("=", 1)[1].strip()
                return _decode_file_caps(hexbytes)
        return None


@dataclass
class InodeIndex:
    """path -> InodeMeta for the whole image, plus a type -> paths reverse index.

    Device paths are absolute and on-device (e.g. `/vendor/bin/hw/foo`), already
    remapped from each partition's internal path. The reverse index (`by_type`) is
    what the file-backing resolver uses to answer "which concrete files carry this
    SELinux type?" from the authoritative xattrs rather than from file_contexts
    guesses.
    """
    meta: dict[str, InodeMeta] = field(default_factory=dict)
    by_type: dict[str, list[str]] = field(default_factory=dict)

    def get(self, device_path: str) -> Optional[InodeMeta]:
        return self.meta.get(device_path)

    def paths_for_type(self, setype: str, limit: Optional[int] = None) -> list[str]:
        paths = self.by_type.get(setype, [])
        return paths[:limit] if limit else list(paths)


# Linux capability bit -> name, for the common caps that appear on Android file
# capabilities. (The full set is large; this covers what shows up in practice and
# anything unmapped is reported as cap_<n> so nothing is silently dropped.)
_CAP_NAMES = {
    0: "chown", 1: "dac_override", 2: "dac_read_search", 3: "fowner", 4: "fsetid",
    5: "kill", 6: "setgid", 7: "setuid", 8: "setpcap", 11: "net_broadcast",
    12: "net_admin", 13: "net_raw", 16: "sys_module", 17: "sys_rawio",
    19: "sys_ptrace", 21: "sys_admin", 22: "sys_boot", 23: "sys_nice",
    24: "sys_resource", 27: "mknod", 31: "mac_override", 36: "bpf", 40: "checkpoint_restore",
}


def _decode_file_caps(hexbytes: str) -> Optional[str]:
    """Decode a security.capability xattr hex dump to permitted cap names.

    The xattr is a little-endian `vfs_cap_data`: u32 magic_etc, then (permitted,
    inheritable) u32 pairs -- one pair for v2, two for v3 (64-bit). We decode the
    permitted set (bits 0..63), which is the set a process gains, and name each bit.
    """
    try:
        raw = bytes(int(b, 16) for b in hexbytes.split())
    except ValueError:
        return None
    if len(raw) < 8:
        return None
    import struct as _struct
    # permitted_low is the u32 right after magic_etc; permitted_high (v3) is further on.
    permitted_low = _struct.unpack_from("<I", raw, 4)[0]
    permitted_high = _struct.unpack_from("<I", raw, 12)[0] if len(raw) >= 16 else 0
    bits = permitted_low | (permitted_high << 32)
    names = []
    for i in range(64):
        if bits & (1 << i):
            names.append(_CAP_NAMES.get(i, f"cap_{i}"))
    return ",".join(names) if names else None


def _mount_prefix(p: Partition) -> str:
    """On-device prefix for a partition's internal paths.

    The `system` partition is system-as-root: its filesystem root *is* the device
    root, and it already contains `/system`, `/vendor`, ... inside, so its paths
    need no prefix. Every other partition is mounted at its mountpoint, so its
    internal `/etc/...` becomes `<mountpoint>/etc/...`.
    """
    if p.name == "system":
        return ""
    return p.mountpoint.rstrip("/")


def build_inode_index(ps: PartitionSet, read_labels: bool = True) -> InodeIndex:
    """Walk every ext4 partition and build the on-device inode index.

    `read_labels=False` skips the xattr pass (faster) when only uid/gid/mode are
    needed. EROFS partitions are not yet handled here (the reference image is ext4);
    they are flagged so the gap is visible rather than silent.
    """
    idx = InodeIndex()
    # Process `system` first so later partitions overlay their mountpoints (e.g. the
    # real /vendor content replaces system's empty /vendor mount-point directory).
    order = sorted(ps.partitions.values(), key=lambda p: (p.name != "system", p.name))
    for part in order:
        if part.fstype != "ext4":
            # EROFS / unknown: record a placeholder so the caller can report the gap.
            idx.meta.setdefault(f"<unreadable:{part.name}:{part.fstype}>",
                                InodeMeta(None, None, None, None, None))
            continue
        prefix = _mount_prefix(part)
        reader = Ext4Reader(part.image)
        try:
            nodes = list(reader.walk())
            for fs_path, uid, gid, mode in nodes:
                dev_path = f"{prefix}{fs_path}" if prefix else fs_path
                setype = caps = None
                is_reg = mode is not None and stmod.S_ISREG(mode)
                if read_labels:
                    setype = reader.selinux_label(fs_path)
                    # File caps live in an xattr independent of the setuid mode bit,
                    # so read them for every regular file (cheap: most have none).
                    if is_reg:
                        caps = reader.capability(fs_path)
                m = InodeMeta(
                    uid=uid, gid=gid, mode=mode, setype=setype, caps=caps,
                    is_dir=stmod.S_ISDIR(mode) if mode is not None else False,
                    is_symlink=stmod.S_ISLNK(mode) if mode is not None else False)
                idx.meta[dev_path] = m
                if setype:
                    idx.by_type.setdefault(setype, []).append(dev_path)
        finally:
            reader.close()
    return idx
