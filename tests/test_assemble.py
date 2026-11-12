"""Tests for policy-assembly failure reporting (the 'No such file: sepolicy' bug)."""

from __future__ import annotations

import pytest

from sesurface.policy.assemble import PolicyAssemblyError, assemble


class _NoPolicyFiles:
    """An image with no precompiled policy and no CIL inputs."""

    def exists(self, path):
        return False

    def read_text(self, path):
        return None

    def extract_to(self, device_path, dest):
        return False


def test_assemble_raises_clear_error_when_nothing_found(tmp_path):
    with pytest.raises(PolicyAssemblyError) as ei:
        assemble(_NoPolicyFiles(), str(tmp_path))
    msg = str(ei.value)
    # The message must be actionable, not a bare path.
    assert "No SELinux policy could be assembled" in msg
    assert "precompiled" in msg and "CIL" in msg
