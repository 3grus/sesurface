"""Read an EROFS image without mounting and without root.

EROFS is the read-only filesystem Android 13+ ships for many partitions and for
APEX payloads. The reference emulator image is ext4 throughout, so this reader is
the companion to `inode.py::Ext4Reader` for images (and APEX payloads) that use
EROFS instead.

Two jobs, two mechanisms, each chosen for what it can do without privilege:

  * **Metadata + xattrs** (uid/gid/mode and the `security.selinux` label) are parsed
    straight from the on-disk EROFS structures in pure Python. This is what the DAC
    gate and -- crucially -- the locator's exec-type -> binary map depend on, and the
    `security.selinux` xattr cannot be recovered any other way without root (a plain
    `fsck.erofs --extract` as a normal user drops it). The inode and directory
    metadata are never compressed, so this works regardless of file-data compression.

  * **File bytes** (an ELF to `readelf`, a jar to decompile) come from
    `fsck.erofs --extract`, which transparently decompresses lz4/lzma file data. We
    extract once into a cache dir and read the files back. Uncompressed files are also
    readable directly from the parsed layout, which we use as a fast path.

Only the uncompressed on-disk inode/dirent layout is parsed here (that is all the
metadata path needs); compressed *file* data is handled by `fsck.erofs`, never by the
Python parser. A structure we cannot parse degrades to "unknown", never to a wrong
default -- same discipline as the ext4 reader.
"""

from __future__ import annotations

import mmap
import os
import stat as stmod
import struct
import subprocess
from typing import Iterator, Optional

_EROFS_MAGIC = 0xE0F5E1E2

# erofs_xattr_entry.e_name_index -> the implied full-name prefix.
_XATTR_PREFIX = {1: "user.", 2: "", 3: "", 4: "trusted.", 6: "security."}

# EROFS dirent file_type values (mirror the on-disk d_type).
_EROFS_FT_DIR = 2


class ErofsReader:
    """Parse an EROFS image's tree + xattrs, and read file bytes via fsck.erofs.

    The on-disk reader mirrors the surface of `Ext4Reader` that `inode.py` and
    `extract.py` use: `walk()`, `selinux_label(path)`, `capability(path)`, plus a
    `read_bytes`/`extract` for file contents and `close()`.
    """

    def __init__(self, image: str, extract_cache: Optional[str] = None):
        self.image = image
        self._f = open(image, "rb")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self._extract_cache = extract_cache
        self._extracted = False          # whether fsck.erofs --extract has run
        # path -> nid, filled lazily by _resolve so repeated reads are cheap.
        self._nid_cache: dict[str, Optional[int]] = {}
        self._parse_super()

    # ---- superblock ------------------------------------------------------ #

    def _parse_super(self) -> None:
        sb = self._mm[0x400:0x400 + 128]
        magic, = struct.unpack_from("<I", sb, 0)
        if magic != _EROFS_MAGIC:
            raise ValueError(f"not an EROFS image: {self.image}")
        self.blkszbits = sb[12] or 12
        self.blksz = 1 << self.blkszbits
        self.root_nid, = struct.unpack_from("<H", sb, 14)
        self.meta_blkaddr, = struct.unpack_from("<I", sb, 40)
        self.xattr_blkaddr, = struct.unpack_from("<I", sb, 44)

    # ---- inode ----------------------------------------------------------- #

    def _inode(self, nid: int) -> dict:
        """Decode the inode at `nid` (compact=32B or extended=64B)."""
        off = self.meta_blkaddr * self.blksz + nid * 32
        fmt, = struct.unpack_from("<H", self._mm, off)
        extended = (fmt & 1) == 1
        datalayout = (fmt >> 1) & 7
        xattr_icount, = struct.unpack_from("<H", self._mm, off + 2)
        mode, = struct.unpack_from("<H", self._mm, off + 4)
        if extended:
            size, = struct.unpack_from("<Q", self._mm, off + 8)
            i_u, = struct.unpack_from("<I", self._mm, off + 16)
            uid, = struct.unpack_from("<I", self._mm, off + 24)
            gid, = struct.unpack_from("<I", self._mm, off + 28)
            inode_size = 64
        else:
            size, = struct.unpack_from("<I", self._mm, off + 8)
            i_u, = struct.unpack_from("<I", self._mm, off + 16)
            uid, = struct.unpack_from("<H", self._mm, off + 24)
            gid, = struct.unpack_from("<H", self._mm, off + 26)
            inode_size = 32
        # The xattr area follows the inode struct; its size is derived from icount.
        xattr_size = 0 if xattr_icount == 0 else (xattr_icount - 1) * 4 + 12
        return {
            "nid": nid, "mode": mode, "size": size, "uid": uid, "gid": gid,
            "datalayout": datalayout, "i_u": i_u,
            "xattr_off": off + inode_size, "xattr_icount": xattr_icount,
            "xattr_size": xattr_size, "data_off": off + inode_size + xattr_size,
        }

    # ---- raw data (uncompressed layouts only) ---------------------------- #

    def _read_data(self, ino: dict) -> Optional[bytes]:
        """Reconstruct an uncompressed inode's data, or None if compressed.

        FLAT_PLAIN (0): contiguous at `i_u` block. FLAT_INLINE (2): the full blocks
        at `i_u`, the final partial block inline right after the inode+xattrs. Any
        compressed layout (1/3/...) returns None -- those go through fsck.erofs.
        """
        size, layout = ino["size"], ino["datalayout"]
        if layout == 0:                       # FLAT_PLAIN
            start = ino["i_u"] * self.blksz
            return bytes(self._mm[start:start + size])
        if layout == 2:                       # FLAT_INLINE
            nfull = size // self.blksz
            tail = size - nfull * self.blksz
            buf = bytearray()
            start = ino["i_u"] * self.blksz
            buf += self._mm[start:start + nfull * self.blksz]
            buf += self._mm[ino["data_off"]:ino["data_off"] + tail]
            return bytes(buf)
        return None

    # ---- directory ------------------------------------------------------- #

    def _readdir(self, ino: dict) -> list[tuple[str, int, int]]:
        """Return (name, child_nid, file_type) for a directory inode."""
        data = self._read_data(ino)
        if data is None:
            return []
        entries: list[tuple[str, int, int]] = []
        size = ino["size"]
        for blk_start in range(0, size, self.blksz):
            blk = data[blk_start:blk_start + min(self.blksz, size - blk_start)]
            if len(blk) < 12:
                continue
            first_nameoff, = struct.unpack_from("<H", blk, 8)
            count = first_nameoff // 12
            if count == 0 or first_nameoff > len(blk):
                continue
            for i in range(count):
                doff = i * 12
                nid, = struct.unpack_from("<Q", blk, doff)
                nameoff, = struct.unpack_from("<H", blk, doff + 8)
                ftype = blk[doff + 10]
                nend = (struct.unpack_from("<H", blk, (i + 1) * 12 + 8)[0]
                        if i + 1 < count else len(blk))
                name = blk[nameoff:nend].split(b"\x00")[0].decode("latin1")
                if name in (".", ".."):
                    continue
                entries.append((name, nid, ftype))
        return entries

    # ---- xattrs ---------------------------------------------------------- #

    def _xattrs(self, ino: dict) -> dict[str, bytes]:
        """Decode an inode's xattrs (inline + shared) to {full_name: value}."""
        if ino["xattr_icount"] == 0:
            return {}
        base = ino["xattr_off"]
        h_shared_count = self._mm[base + 4]
        out: dict[str, bytes] = {}
        # Shared entries: each is a 4-byte-unit index into the shared xattr region.
        for s in range(h_shared_count):
            idx, = struct.unpack_from("<I", self._mm, base + 12 + s * 4)
            epos = self.xattr_blkaddr * self.blksz + idx * 4
            self._read_xattr_entry(epos, out)
        # Inline entries follow the shared-index array, to the end of the xattr area.
        pos = base + 12 + h_shared_count * 4
        end = base + ino["xattr_size"]
        while pos + 4 <= end:
            consumed = self._read_xattr_entry(pos, out)
            if consumed <= 0:
                break
            pos += (consumed + 3) & ~3
        return out

    def _read_xattr_entry(self, pos: int, out: dict[str, bytes]) -> int:
        """Parse one erofs_xattr_entry at `pos`; return its unpadded byte length."""
        e_name_len = self._mm[pos]
        e_name_index = self._mm[pos + 1]
        e_value_size, = struct.unpack_from("<H", self._mm, pos + 2)
        if e_name_len == 0:
            return 0
        name = bytes(self._mm[pos + 4:pos + 4 + e_name_len])
        val = bytes(self._mm[pos + 4 + e_name_len:pos + 4 + e_name_len + e_value_size])
        prefix = _XATTR_PREFIX.get(e_name_index, "")
        out[prefix + name.decode("latin1")] = val
        return 4 + e_name_len + e_value_size

    # ---- path resolution ------------------------------------------------- #

    def _resolve(self, fs_path: str) -> Optional[int]:
        """Resolve an absolute in-image path to its nid (or None)."""
        if fs_path in self._nid_cache:
            return self._nid_cache[fs_path]
        nid: Optional[int] = self.root_nid
        for part in fs_path.strip("/").split("/"):
            if not part:
                continue
            ino = self._inode(nid)
            if not stmod.S_ISDIR(ino["mode"]):
                nid = None
                break
            nxt = None
            for name, child, _ft in self._readdir(ino):
                if name == part:
                    nxt = child
                    break
            if nxt is None:
                nid = None
                break
            nid = nxt
        self._nid_cache[fs_path] = nid
        return nid

    # ---- public surface (mirrors Ext4Reader) ----------------------------- #

    def walk(self) -> Iterator[tuple[str, int, int, int]]:
        """Yield (fs_path, uid, gid, mode) for every node, depth-first."""
        stack = [("/", self.root_nid)]
        self._nid_cache["/"] = self.root_nid
        while stack:
            path, nid = stack.pop()
            ino = self._inode(nid)
            if path != "/":
                yield (path, ino["uid"], ino["gid"], ino["mode"])
            if stmod.S_ISDIR(ino["mode"]):
                for name, child, _ft in self._readdir(ino):
                    child_path = f"{path.rstrip('/')}/{name}" if path != "/" else f"/{name}"
                    self._nid_cache[child_path] = child
                    stack.append((child_path, child))

    def selinux_label(self, fs_path: str) -> Optional[str]:
        """The SELinux type from a node's security.selinux xattr, or None."""
        nid = self._resolve(fs_path)
        if nid is None:
            return None
        val = self._xattrs(self._inode(nid)).get("security.selinux")
        if not val:
            return None
        ctx = val.split(b"\x00", 1)[0].decode("latin1")
        bits = ctx.split(":")
        return bits[2] if len(bits) >= 3 else None

    def capability(self, fs_path: str) -> Optional[str]:
        """File capabilities (security.capability) decoded to names, or None."""
        nid = self._resolve(fs_path)
        if nid is None:
            return None
        val = self._xattrs(self._inode(nid)).get("security.capability")
        if not val:
            return None
        from .inode import _decode_file_caps
        return _decode_file_caps(" ".join(f"{b:02x}" for b in val))

    def read_bytes(self, fs_path: str) -> Optional[bytes]:
        """File contents: direct for uncompressed data, else via fsck.erofs."""
        nid = self._resolve(fs_path)
        if nid is None:
            return None
        ino = self._inode(nid)
        if not stmod.S_ISREG(ino["mode"]):
            return None
        direct = self._read_data(ino)
        if direct is not None:
            return direct
        host = self._extract_path(fs_path)
        if host and os.path.exists(host):
            with open(host, "rb") as f:
                return f.read()
        return None

    def extract(self, fs_path: str, dest_path: str) -> bool:
        """Write a file's bytes to `dest_path` (for tools that need a real file)."""
        data = self.read_bytes(fs_path)
        if data is None:
            return False
        with open(dest_path, "wb") as f:
            f.write(data)
        return True

    # ---- fsck.erofs extraction (decompresses) ---------------------------- #

    def _ensure_extracted(self) -> Optional[str]:
        """Extract the whole image once with fsck.erofs; return the root dir."""
        if self._extract_cache is None:
            import tempfile
            self._extract_cache = tempfile.mkdtemp(prefix="sesurface-erofs-")
        root = os.path.join(self._extract_cache, "root")
        if self._extracted and os.path.isdir(root):
            return root
        os.makedirs(self._extract_cache, exist_ok=True)
        try:
            subprocess.run(
                ["fsck.erofs", f"--extract={root}", "--no-preserve", "--overwrite",
                 self.image],
                capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.SubprocessError):
            return None
        self._extracted = os.path.isdir(root)
        return root if self._extracted else None

    def _extract_path(self, fs_path: str) -> Optional[str]:
        root = self._ensure_extracted()
        if root is None:
            return None
        return os.path.join(root, fs_path.lstrip("/"))

    def close(self) -> None:
        try:
            self._mm.close()
        except Exception:
            pass
        try:
            self._f.close()
        except Exception:
            pass
