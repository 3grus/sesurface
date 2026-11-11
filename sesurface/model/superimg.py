"""Parse Android "super" dynamic-partition images (liblp metadata).

Since Android 10, the read-only partitions (system, system_ext, product, vendor,
odm) are not separate image files; they are *logical* partitions packed inside one
`super` partition, described by liblp metadata. AOSP ships `lpunpack` to split
them, but it is not packaged on Ubuntu, so we parse the (well-documented, stable)
metadata ourselves. This is ~1 struct per concept and needs no third-party code.

We only need the read path: given the super image and the byte offset where the
super partition begins, return each logical partition's name and the byte extents
it occupies, so the caller can carve it out and read its filesystem.

Layout of a super partition (all offsets relative to the super partition start):

    [0,        4096)  reserved
    [4096,     8192)  primary geometry   (LpMetadataGeometry, 4096-byte slot)
    [8192,    12288)  backup  geometry
    [12288,   ... )   primary metadata   (header + tables)
    ...               backup metadata slots

Reference: AOSP `system/core/fs_mgr/liblp/include/liblp/metadata_format.h`.
Validated against an Android 13 x86_64 emulator super image.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# Magic numbers from metadata_format.h.
_GEOMETRY_MAGIC = 0x616C4467   # "gDla" little-endian.
_HEADER_MAGIC = 0x414C5030     # "AL P0" -> LP metadata header.

_RESERVED = 4096
_GEOMETRY_SIZE = 4096          # Each geometry copy occupies a 4096-byte slot.


@dataclass(frozen=True)
class LogicalPartition:
    """One logical partition and where its bytes live in the super image."""
    name: str
    # Extents as (absolute_byte_offset_in_super_image, length_bytes). Usually one,
    # contiguous, but the format allows several, so we keep a list.
    extents: list[tuple[int, int]]

    @property
    def size(self) -> int:
        return sum(length for _, length in self.extents)


def parse_super(image_path: str, super_offset: int) -> list[LogicalPartition]:
    """Parse the liblp metadata of a super partition.

    `super_offset` is the byte offset within `image_path` where the super partition
    begins (0 if the file is a bare super image; otherwise the GPT partition start).
    Extent offsets in the result are absolute within `image_path`, ready for `dd`.
    """
    with open(image_path, "rb") as f:
        def rd(rel: int, n: int) -> bytes:
            f.seek(super_offset + rel)
            return f.read(n)

        # --- geometry: tells us the metadata slot size and count ------------- #
        geo = rd(_RESERVED, _GEOMETRY_SIZE)
        magic, _struct_size = struct.unpack_from("<II", geo, 0)
        if magic != _GEOMETRY_MAGIC:
            raise ValueError(
                f"not a super image: geometry magic {magic:#x} != {_GEOMETRY_MAGIC:#x} "
                f"at offset {super_offset + _RESERVED}")
        # struct: magic(4) struct_size(4) checksum[32] metadata_max_size(4)
        #         metadata_slot_count(4) logical_block_size(4)
        metadata_max_size, slot_count, _lbs = struct.unpack_from("<III", geo, 8 + 32)

        # --- primary metadata: header + tables ------------------------------- #
        # Primary metadata follows the reserved area and the two geometry slots.
        meta_off = _RESERVED + _GEOMETRY_SIZE * 2
        hdr = rd(meta_off, 256)
        hmagic, _major, _minor, header_size = struct.unpack_from("<IHHI", hdr, 0)
        if hmagic != _HEADER_MAGIC:
            raise ValueError(f"bad LP metadata header magic {hmagic:#x}")
        # LpMetadataHeader fixed layout:
        #   magic(4) major(2) minor(2) header_size(4) header_checksum[32]
        #   tables_size(4) tables_checksum[32]
        #   then four table descriptors, each: offset(4) num_entries(4) entry_size(4)
        #   in order: partitions, extents, groups, block_devices.
        tables_size, = struct.unpack_from("<I", hdr, 4 + 2 + 2 + 4 + 32)
        desc_base = 4 + 2 + 2 + 4 + 32 + 4 + 32
        p_off, p_num, p_es = struct.unpack_from("<III", hdr, desc_base)
        e_off, e_num, e_es = struct.unpack_from("<III", hdr, desc_base + 12)

        tables = rd(meta_off + header_size, tables_size)

        # Extent table: num_sectors(u64) target_type(u32) target_data(u64) target_source(u32)
        # target_type 0 == LINEAR; target_data is the start sector within the super
        # block device (512-byte sectors), which is the super partition itself.
        extents: list[tuple[int, int]] = []
        for i in range(e_num):
            rec = tables[e_off + i * e_es: e_off + i * e_es + e_es]
            num_sectors, = struct.unpack_from("<Q", rec, 0)
            target_data, = struct.unpack_from("<Q", rec, 12)
            abs_off = super_offset + target_data * 512
            extents.append((abs_off, num_sectors * 512))

        # Partition table: name[36] attributes(u32) first_extent_index(u32)
        #                  num_extents(u32) group_index(u32)
        parts: list[LogicalPartition] = []
        for i in range(p_num):
            rec = tables[p_off + i * p_es: p_off + i * p_es + p_es]
            name = rec[:36].split(b"\x00")[0].decode("ascii", "replace")
            _attrs, first_extent, num_ext, _group = struct.unpack_from("<IIII", rec, 36)
            parts.append(LogicalPartition(
                name=name,
                extents=extents[first_extent: first_extent + num_ext]))
        return parts
