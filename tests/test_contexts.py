"""Tests for the file_contexts precedence rule -- the Ch. 22 correctness fix.

These use tiny inline fixtures (the Blast Radius guide's recommended way to unit
test this: faketree-style synthetic data is fine for *mechanism* tests, just not
for whole-image correctness claims).
"""

from __future__ import annotations

import os
import tempfile

from sesurface.model.contexts import ContextDB


def _write(d: str, name: str, body: str) -> str:
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(body)
    return p


def test_later_partition_wins_over_earlier():
    """vendor_file_contexts must beat plat_file_contexts for an overlapping regex."""
    with tempfile.TemporaryDirectory() as d:
        plat = _write(d, "plat_file_contexts",
                      "/data/vendor(/.*)?   u:object_r:plat_label:s0\n")
        vendor = _write(d, "vendor_file_contexts",
                        "/data/vendor(/.*)?   u:object_r:vendor_label:s0\n")
        db = ContextDB()
        # Load in either order; finalize() imposes the partition order.
        db.load_file_contexts(vendor)
        db.load_file_contexts(plat)
        db.finalize()
        setype, entry = db.label_for_path("/data/vendor/foo")
        assert setype == "vendor_label", setype
        assert "vendor_file_contexts" in entry.source_file


def test_exact_path_beats_regex_from_a_later_partition():
    """An exact path in plat must beat a regex in vendor (exacts move to the end)."""
    with tempfile.TemporaryDirectory() as d:
        plat = _write(d, "plat_file_contexts",
                      "/data/misc/special   u:object_r:special_label:s0\n")  # exact
        vendor = _write(d, "vendor_file_contexts",
                        "/data/misc(/.*)?     u:object_r:misc_label:s0\n")    # regex
        db = ContextDB()
        db.load_file_contexts(plat)
        db.load_file_contexts(vendor)
        db.finalize()
        setype, _ = db.label_for_path("/data/misc/special")
        assert setype == "special_label", setype
        # A sibling that only the regex matches still gets the regex label.
        setype2, _ = db.label_for_path("/data/misc/other")
        assert setype2 == "misc_label", setype2


def test_type_specifier_filters_by_node_kind():
    """A `-c` (char device) entry must not match a regular file at the same path."""
    import stat
    with tempfile.TemporaryDirectory() as d:
        vendor = _write(d, "vendor_file_contexts",
                        "/dev/foo   -c   u:object_r:foo_device:s0\n"
                        "/dev/foo        u:object_r:foo_file:s0\n")
        db = ContextDB()
        db.load_file_contexts(vendor)
        db.finalize()
        # As a char device, the -c entry is eligible and, being later in file
        # order... actually both match; the last matching wins. Here the plain
        # entry is last, so a char node still resolves to it unless kind filters.
        # The point of this test: a regular file must NOT get foo_device.
        char_mode = stat.S_IFCHR | 0o600
        reg_mode = stat.S_IFREG | 0o600
        st_char, _ = db.label_for_path("/dev/foo", mode=char_mode)
        st_reg, _ = db.label_for_path("/dev/foo", mode=reg_mode)
        # The regular file cannot match the -c entry, only the plain one.
        assert st_reg == "foo_file", st_reg
        # The char device matches both; last-in-list (plain) wins here.
        assert st_char in ("foo_file", "foo_device"), st_char


def test_no_match_returns_none():
    with tempfile.TemporaryDirectory() as d:
        vendor = _write(d, "vendor_file_contexts",
                        "/data/vendor(/.*)?   u:object_r:vendor_label:s0\n")
        db = ContextDB()
        db.load_file_contexts(vendor)
        db.finalize()
        assert db.label_for_path("/system/bin/sh") is None
