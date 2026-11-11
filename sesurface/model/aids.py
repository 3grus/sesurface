"""Resolve Android user/group *names* to numeric uid/gid (AIDs).

init `.rc` service blocks and `ueventd.rc` lines name their owner by string --
`user cameraserver`, `group audio camera input`, `/dev/null 0666 root root`. The DAC
gate works in numbers (an inode's uid is 1047, not "cameraserver"), so we need the
name->number map Android calls the "AID" table.

Most AIDs are compile-time constants baked into every Android build
(`system/core/libcutils/include/private/android_filesystem_config.h`); we embed that
core table below. OEMs can add their own in `/system/etc/passwd` + `/vendor/etc/passwd`
(and matching `group` files), so we overlay those from the image when present. The
result is authoritative for this specific device.

An AID we cannot resolve is left as None rather than guessed -- a wrong uid would
silently flip a DAC verdict, which is worse than an honest "unknown".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# The core AID table: names Android assigns a fixed number to on every build.
# uid and gid share this namespace for the "oem"/service names; a handful of the
# 3000-range entries are group-only (network capability groups) but live here too
# because `group` lines reference them. Kept deliberately explicit so it is auditable
# against android_filesystem_config.h rather than computed.
_CORE_AIDS: dict[str, int] = {
    "root": 0, "daemon": 1, "bin": 2,
    "system": 1000, "radio": 1001, "bluetooth": 1002, "graphics": 1003,
    "input": 1004, "audio": 1005, "camera": 1006, "log": 1007, "compass": 1008,
    "mount": 1009, "wifi": 1010, "adb": 1011, "install": 1012, "media": 1013,
    "dhcp": 1014, "sdcard_rw": 1015, "vpn": 1016, "keystore": 1017, "usb": 1018,
    "drm": 1019, "mdnsr": 1020, "gps": 1021, "media_rw": 1023, "mtp": 1024,
    "drmrpc": 1026, "nfc": 1027, "sdcard_r": 1028, "clat": 1029, "loop_radio": 1030,
    "mediadrm": 1031, "package_info": 1032, "sdcard_pics": 1033, "sdcard_av": 1034,
    "sdcard_all": 1035, "logd": 1036, "shared_relro": 1037, "dbus": 1038,
    "tlsdate": 1039, "mediaex": 1040, "audioserver": 1041, "metrics_coll": 1042,
    "metricsd": 1043, "webserv": 1044, "debuggerd": 1045, "mediacodec": 1046,
    "cameraserver": 1047, "firewall": 1048, "trunks": 1049, "nvram": 1050,
    "dns": 1051, "dns_tether": 1052, "webview_zygote": 1053, "vehicle_network": 1054,
    "media_audio": 1055, "media_video": 1056, "media_image": 1057, "tombstoned": 1058,
    "media_obb": 1059, "ese": 1060, "ota_update": 1061, "automotive_evs": 1062,
    "lowpan": 1063, "hsm": 1064, "reserved_disk": 1065, "statsd": 1066,
    "incidentd": 1067, "secure_element": 1068, "lmkd": 1069, "llkd": 1070,
    "iorapd": 1071, "gpu_service": 1072, "network_stack": 1073, "gsid": 1074,
    "fsverity_cert": 1075, "credstore": 1076, "external_storage": 1077,
    "ext_data_rw": 1078, "ext_obb_rw": 1079, "context_hub": 1080,
    "virtualizationservice": 1081, "artd": 1082, "ueventd": 1083, "dice_maintenance": 1084,
    "nobody": 9999,
    # Interactive / developer AIDs.
    "shell": 2000, "cache": 2001, "diag": 2002,
    # Network-capability groups (group-only, referenced by `group` lines).
    "net_bt_admin": 3001, "net_bt": 3002, "inet": 3003, "net_raw": 3004,
    "net_admin": 3005, "net_bw_stats": 3006, "net_bw_acct": 3007, "net_bt_stack": 3008,
    "readproc": 3009, "wakelock": 3010, "uhid": 3011, "readtracefs": 3012,
}


@dataclass
class AidDb:
    """Name->number for uids and gids, core table overlaid with the image's passwd/group."""
    uids: dict[str, int] = field(default_factory=dict)
    gids: dict[str, int] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)   # which files contributed.

    def uid(self, name: str) -> Optional[int]:
        return self.uids.get(name)

    def gid(self, name: str) -> Optional[int]:
        # gids default to the uids table when a name is not group-specific, because
        # Android's AID namespace is shared (the `audio` group gid == the audio AID).
        return self.gids.get(name, self.uids.get(name))


def load_aids(files) -> AidDb:
    """Build the AID table: the embedded core, overlaid with the image's own entries.

    `files` is an `ImageFiles`. `/system/etc/passwd` etc. are `name:x:uid:gid:...`;
    `group` files are `name:x:gid:members`. OEM entries override the core ones for
    this device (rare, but the whole point of reading the image is device accuracy).
    """
    db = AidDb(uids=dict(_CORE_AIDS), gids=dict(_CORE_AIDS))

    for path in ("/system/etc/passwd", "/system_ext/etc/passwd",
                 "/product/etc/passwd", "/vendor/etc/passwd",
                 "/vendor/odm/etc/passwd", "/odm/etc/passwd"):
        text = files.read_text(path)
        if not text:
            continue
        got = 0
        for line in text.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 4 and parts[0]:
                try:
                    db.uids[parts[0]] = int(parts[2])
                    db.gids.setdefault(parts[0], int(parts[3]))
                    got += 1
                except ValueError:
                    continue
        if got:
            db.sources.append(f"{path} ({got})")

    for path in ("/system/etc/group", "/system_ext/etc/group",
                 "/product/etc/group", "/vendor/etc/group",
                 "/vendor/odm/etc/group", "/odm/etc/group"):
        text = files.read_text(path)
        if not text:
            continue
        got = 0
        for line in text.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 3 and parts[0]:
                try:
                    db.gids[parts[0]] = int(parts[2])
                    got += 1
                except ValueError:
                    continue
        if got:
            db.sources.append(f"{path} ({got})")

    return db
