"""Mechanism tests for the inverse ('who can touch this path') query.

Like the other unit tests here these use tiny inline fixtures and light fakes --
they exercise the path->label resolution precedence and the reverse DAC check,
the parts that do not need a real setools policy. The full TE reverse query is
covered by the documented end-to-end run against a real image.
"""

from __future__ import annotations

import os
import stat
import tempfile
from types import SimpleNamespace

from sesurface.model.contexts import ContextDB
from sesurface.model.inode import InodeIndex, InodeMeta
from sesurface.policy.policy import GenfsLabel
from sesurface.types import Subject, UidClass
from sesurface import reverse


def _fake_policy(genfs=None):
    return SimpleNamespace(genfs_labels=lambda: list(genfs or []))


def _fake_model(inodes=None, contexts=None):
    return SimpleNamespace(inodes=inodes or InodeIndex(),
                           contexts=contexts or ContextDB(),
                           ueventd=None, aids=None)


def _ctxdb(body):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "vendor_file_contexts")
        open(p, "w").write(body)
        db = ContextDB()
        db.load_file_contexts(p)
        db.finalize()
        return db


# --- path -> label precedence --------------------------------------------- #

def test_xattr_label_wins_for_on_image_file():
    idx = InodeIndex()
    idx.meta["/system/bin/foo"] = InodeMeta(
        uid=0, gid=0, mode=stat.S_IFREG | 0o755, setype="system_file", caps=None)
    lab = reverse.resolve_path_label(_fake_model(inodes=idx), _fake_policy(),
                                     "/system/bin/foo")
    assert lab.source == "xattr"
    assert lab.setype == "system_file"
    assert lab.tclass == "file"


def test_genfscon_label_for_proc_path():
    gl = [GenfsLabel(fs="proc", path="/net", setype="proc_net")]
    lab = reverse.resolve_path_label(_fake_model(), _fake_policy(gl), "/proc/net/tcp")
    assert lab.source == "genfscon"
    assert lab.setype == "proc_net"


def test_file_contexts_label_for_runtime_path():
    db = _ctxdb("/data/vendor/wifi(/.*)?   u:object_r:wifi_data_file:s0\n")
    lab = reverse.resolve_path_label(_fake_model(contexts=db), _fake_policy(),
                                     "/data/vendor/wifi/x")
    assert lab.source == "file_contexts"
    assert lab.setype == "wifi_data_file"


def test_class_inferred_from_file_contexts_spec():
    db = _ctxdb("/dev/kgsl-3d0   -c   u:object_r:gpu_device:s0\n")
    lab = reverse.resolve_path_label(_fake_model(contexts=db), _fake_policy(),
                                     "/dev/kgsl-3d0")
    assert lab.setype == "gpu_device"
    assert lab.tclass == "chr_file"


def test_unlabelled_path_reports_none():
    lab = reverse.resolve_path_label(_fake_model(), _fake_policy(), "/no/such/thing")
    assert lab.source == "none"
    assert lab.setype is None


def test_genfs_longest_prefix_wins():
    gl = [GenfsLabel(fs="sysfs", path="/", setype="sysfs"),
          GenfsLabel(fs="sysfs", path="/class/power_supply", setype="sysfs_batteryinfo")]
    got = reverse._genfs_lookup(_fake_policy(gl), "/sys/class/power_supply/battery/capacity")
    assert got.setype == "sysfs_batteryinfo"


# --- reverse DAC on a concrete path --------------------------------------- #

def _app_subject():
    return Subject(domain="untrusted_app", uid_class=UidClass.APP, uid=10123, gids=())


def _idx_with_tree(dir_mode):
    idx = InodeIndex()
    idx.meta["/d"] = InodeMeta(uid=0, gid=0, mode=stat.S_IFDIR | dir_mode,
                               setype="some_dir", caps=None)
    idx.meta["/d/f"] = InodeMeta(uid=0, gid=0, mode=stat.S_IFREG | 0o644,
                                 setype="some_file", caps=None)
    return idx


def test_reverse_dac_blocked_by_private_ancestor():
    idx = _idx_with_tree(0o700)          # /d not searchable by "other"
    model = _fake_model(inodes=idx)
    lab = reverse.PathLabel("/d/f", "some_file", "file", idx.get("/d/f"), "xattr")
    v = reverse._reverse_dac(_app_subject(), model, lab, frozenset({"read"}))
    assert v.decision.value == "deny", v.evidence


def test_reverse_dac_allowed_when_path_world_traversable():
    idx = _idx_with_tree(0o755)          # /d searchable by "other", /f 0644
    model = _fake_model(inodes=idx)
    lab = reverse.PathLabel("/d/f", "some_file", "file", idx.get("/d/f"), "xattr")
    v = reverse._reverse_dac(_app_subject(), model, lab, frozenset({"read"}))
    assert v.decision.value == "allow", v.evidence


def test_reverse_dac_unknown_for_runtime_path():
    model = _fake_model()                 # empty inode index
    lab = reverse.PathLabel("/data/misc/x", "some_file", "file", None, "file_contexts")
    v = reverse._reverse_dac(_app_subject(), model, lab, frozenset({"read"}))
    assert v.decision.value == "unknown", v.evidence
