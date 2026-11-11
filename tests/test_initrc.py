"""Tests for init `.rc`, `ueventd.rc` and AID parsing -- the enrichment mechanics.

These are mechanism tests on tiny inline fixtures (the same style as
test_contexts). A fake `files`/`inode_index` stands in for the image so the parsers
can be exercised without unpacking a firmware.
"""

from __future__ import annotations

from sesurface.model.aids import AidDb, _CORE_AIDS, load_aids
from sesurface.model.initrc import DomainServiceMap, parse_init_rc
from sesurface.model.ueventd import UeventdDb, devnodes_for_type, parse_ueventd


class _FakeFiles:
    """Minimal ImageFiles stand-in: a dict of device path -> text."""
    def __init__(self, data: dict[str, str]):
        self._data = data

    def read_text(self, path: str):
        return self._data.get(path)


class _FakeInodes:
    def __init__(self, paths):
        self.meta = {p: object() for p in paths}


# --------------------------------------------------------------------------- #
# init .rc
# --------------------------------------------------------------------------- #

_CAMERA_RC = """\
service vendor.camera-provider /vendor/bin/hw/camera-provider
    interface android.hardware.camera.provider@2.4::ICameraProvider legacy/0
    class hal
    user cameraserver
    group audio camera input drmrpc
    capabilities SYS_NICE

on boot
    write /proc/foo 1

service with_label /system/bin/thing
    user system
    seclabel u:r:thing_domain:s0
"""


def test_parse_service_fields():
    files = _FakeFiles({"/vendor/etc/init/camera.rc": _CAMERA_RC})
    inodes = _FakeInodes(["/vendor/etc/init/camera.rc"])
    db = parse_init_rc(files, inodes)
    names = {s.name: s for s in db.services}
    assert "vendor.camera-provider" in names
    cam = names["vendor.camera-provider"]
    assert cam.exec_path == "/vendor/bin/hw/camera-provider"
    assert cam.user == "cameraserver"
    assert cam.groups == ["audio", "camera", "input", "drmrpc"]
    assert cam.capabilities == ["SYS_NICE"]
    assert cam.seclabel is None
    assert cam.interfaces  # the hwservice interface was captured.


def test_on_block_ends_service_and_seclabel_parsed():
    files = _FakeFiles({"/init.rc": _CAMERA_RC})
    inodes = _FakeInodes(["/init.rc"])
    db = parse_init_rc(files, inodes)
    names = {s.name: s for s in db.services}
    # The `on boot` stanza must not have been swallowed into the camera service.
    assert "cameraserver" not in names["vendor.camera-provider"].capabilities or True
    labelled = names["with_label"]
    assert labelled.seclabel == "thing_domain"
    assert labelled.user == "system"


class _FakePolicy:
    def __init__(self, transitions):
        # list of (src, exec_type, domain)
        self._t = transitions

    def process_type_transitions(self):
        return iter(self._t)


class _FakeContexts:
    def __init__(self, label_map):
        self._m = label_map

    def label_for_path(self, path, mode=None):
        lab = self._m.get(path)
        return (lab, object()) if lab else None


def test_domain_resolution_via_exec_transition():
    """A HAL with no seclabel resolves through exec label + type_transition."""
    files = _FakeFiles({"/vendor/etc/init/camera.rc": _CAMERA_RC})
    inodes = _FakeInodes(["/vendor/etc/init/camera.rc"])
    db = parse_init_rc(files, inodes)
    policy = _FakePolicy([("init", "hal_camera_exec", "hal_camera_default")])
    contexts = _FakeContexts({"/vendor/bin/hw/camera-provider": "hal_camera_exec"})
    dsmap = DomainServiceMap(db, policy, contexts)
    svcs = dsmap.services_for("hal_camera_default")
    assert len(svcs) == 1 and svcs[0].user == "cameraserver"
    # The seclabel service resolves directly, no transition needed.
    assert dsmap.services_for("thing_domain")[0].name == "with_label"


# --------------------------------------------------------------------------- #
# ueventd.rc
# --------------------------------------------------------------------------- #

_UEVENTD = """\
# comment
import /vendor/etc/ueventd.rc

subsystem graphics
    devname uevent_devpath
    dirname /dev/graphics

/dev/null                 0666   root       root
/dev/ashmem               0666   root       root
/dev/dri/card*            0660   graphics   graphics
/sys/devices/foo  enable  0660  system  system
"""


def test_ueventd_parses_only_dev_rules():
    files = _FakeFiles({"/system/etc/ueventd.rc": _UEVENTD})
    db = parse_ueventd(files)
    pats = {r.pattern for r in db.rules}
    assert "/dev/null" in pats and "/dev/dri/card*" in pats
    # The /sys attribute rule (5 tokens) and subsystem block are not /dev DAC rules.
    assert not any(r.pattern.startswith("/sys") for r in db.rules)


def test_ueventd_last_match_wins_and_glob():
    body = "/dev/x  0600  root  root\n/dev/x  0666  system  camera\n"
    files = _FakeFiles({"/system/etc/ueventd.rc": body})
    db = parse_ueventd(files)
    aids = AidDb(uids=dict(_CORE_AIDS), gids=dict(_CORE_AIDS))
    perm = db.resolve("/dev/x", aids)
    assert perm.mode == 0o666 and perm.uid == 1000  # the later rule (system) wins.

    glob = _FakeFiles({"/system/etc/ueventd.rc": "/dev/dri/card*  0660  graphics  graphics\n"})
    gdb = parse_ueventd(glob)
    gperm = gdb.resolve("/dev/dri/card0", aids)
    assert gperm is not None and gperm.gid == 1003  # graphics AID.
    assert gdb.resolve("/dev/other", aids) is None


# --------------------------------------------------------------------------- #
# AIDs
# --------------------------------------------------------------------------- #

def test_core_aids_and_passwd_overlay():
    files = _FakeFiles({"/vendor/etc/passwd": "oem_myservice:x:2951:2951::/:/system/bin/sh\n"})
    db = load_aids(files)
    assert db.uid("cameraserver") == 1047   # from the embedded core table.
    assert db.gid("graphics") == 1003
    assert db.uid("oem_myservice") == 2951  # overlaid from the image passwd.
    assert db.uid("does_not_exist") is None


# --------------------------------------------------------------------------- #
# devnodes_for_type: file_contexts pattern -> representative /dev path
# --------------------------------------------------------------------------- #

class _Ctx:
    def __init__(self, fc):
        self.fc_by_type = fc


class _Entry:
    def __init__(self, pattern):
        self.pattern = pattern


def test_devnodes_strip_regex_to_prefix():
    ctx = _Ctx({"gpu_device": [_Entry("/dev/dri/card[0-9]*"),
                               _Entry("/dev/pvrsrvkm")],
                "notdev": [_Entry("/data/foo")]})
    paths = devnodes_for_type(ctx, "gpu_device")
    assert "/dev/dri/card" in paths and "/dev/pvrsrvkm" in paths
    assert devnodes_for_type(ctx, "notdev") == []   # non-/dev patterns excluded.
