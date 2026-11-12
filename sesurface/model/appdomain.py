"""Resolve which on-disk APK(s) run in each app SELinux domain.

For the "blast radius" question -- if a subject can reach or become an app domain,
*whose code* is that? -- we need to go from an app domain (`platform_app`, `priv_app`,
`system_app`, `bluetooth`, `nfc`, ...) to the concrete APK on a partition. Android
decides an app's domain at install time from `seapp_contexts`, matching on the app's
UID class, its signing-cert `seinfo`, whether it is privileged, its package name, and
its target SDK. We run that same match over every preinstalled APK and invert it to a
domain -> [apk paths] map.

Inputs, and how we recover each without the device:
  * **user** (UID class) -- from the APK manifest's `sharedUserId`
    (`android.uid.system` -> system, `android.uid.phone` -> radio, ...); absent -> `_app`.
  * **seinfo** -- the signing certificate matched against `mac_permissions.xml`
    (`<signer signature="<cert DER hex>"><seinfo value="platform"/>`); no match -> `default`.
  * **isPrivApp** -- the APK lives under a `priv-app/` directory.
  * **name / minTargetSdkVersion** -- package name and target SDK from the manifest.

The honest edges: a user-installed app (plain `untrusted_app`/`isolated_app`) has **no
APK on the image** -- its code is whatever gets side-loaded, so we never invent a file
for it. And matching is a close reimplementation of AOSP's `seapp_context_cmp`
precedence, not the kernel's own code, so results are labelled as a static inference.

Untrusted-data hygiene: APKs are untrusted firmware. We extract each into an isolated
scratch dir, parse it with androguard (which never executes it), and pass paths as args.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Optional

# Directories whose APKs are preinstalled (and thus on the image). User apps live under
# /data/app, which is not part of a read-only firmware image.
_APP_DIR_RE = re.compile(r"/(priv-app|app)/")
# A sharedUserId -> seapp `user=` class. Anything else (incl. none) is a normal `_app`.
_SHARED_UID_USER = {
    "android.uid.system": "system", "android.uid.phone": "radio",
    "android.uid.bluetooth": "bluetooth", "android.uid.nfc": "nfc",
    "android.uid.se": "secure_element", "android.uid.networkstack": "network_stack",
    "android.uid.uwb": "uwb",
}


@dataclass
class AppInfo:
    """What `seapp_contexts` matching needs about one preinstalled APK."""
    path: str                   # on-device APK path
    package: str
    user: str                   # seapp `user=` class (_app, system, radio, ...)
    seinfo: str                 # from mac_permissions, or "default"
    is_priv: bool
    target_sdk: int
    domain: str = ""            # resolved app domain (filled by the resolver)


@dataclass
class AppDomainIndex:
    """domain -> [apk paths], plus per-APK facts, for the locator and the view."""
    by_domain: dict[str, list[str]] = field(default_factory=dict)
    apps: dict[str, AppInfo] = field(default_factory=dict)   # apk path -> AppInfo

    def apks_for_domain(self, domain: str) -> list[str]:
        return list(self.by_domain.get(domain, []))


# --------------------------------------------------------------------------- #
# mac_permissions: signing cert -> seinfo
# --------------------------------------------------------------------------- #

def quiet_androguard() -> None:
    """Silence androguard's logging. v4 uses loguru; older versions use logging.

    androguard logs a line per parsed element at DEBUG, which floods a run that parses
    100+ APKs. We disable both back-ends (idempotent, safe if either is absent).
    """
    try:
        from loguru import logger as _loguru      # androguard 4.x
        _loguru.disable("androguard")
    except Exception:
        pass
    try:
        import logging
        logging.getLogger("androguard").setLevel(logging.ERROR)
        for name in list(logging.root.manager.loggerDict):
            if name.startswith("androguard"):
                logging.getLogger(name).setLevel(logging.ERROR)
    except Exception:
        pass


def load_seinfo_signers(files) -> dict[str, str]:
    """{cert-DER-hex(upper): seinfo} from every mac_permissions.xml on the image."""
    signers: dict[str, str] = {}
    for path in ("/system/etc/selinux/plat_mac_permissions.xml",
                 "/vendor/etc/selinux/vendor_mac_permissions.xml",
                 "/system_ext/etc/selinux/system_ext_mac_permissions.xml",
                 "/product/etc/selinux/product_mac_permissions.xml"):
        txt = files.read_text(path)
        if not txt:
            continue
        for mo in re.finditer(r'<signer\s+signature="([0-9A-Fa-f]+)"\s*>(.*?)</signer>',
                              txt, re.S):
            se = re.search(r'seinfo\s+value="([^"]+)"', mo.group(2))
            if se:
                signers.setdefault(mo.group(1).upper(), se.group(1))
    return signers


# --------------------------------------------------------------------------- #
# seapp_contexts matching (a close port of AOSP seapp_context_cmp precedence)
# --------------------------------------------------------------------------- #

def _name_matches(pkg: str, pat: str) -> bool:
    if pat.endswith("*"):
        return pkg.startswith(pat[:-1])
    return pkg == pat


def _row_matches(row: dict, app: AppInfo) -> bool:
    """True if a preinstalled, owner-user APK satisfies every selector in `row`."""
    # Flags that a normal preinstalled app does not set: a row requiring them is out.
    if row.get("isSystemServer", "false").lower() == "true":
        return False
    if row.get("isEphemeralApp", "false").lower() == "true":
        return False
    if row.get("fromRunAs", "false").lower() == "true":
        return False
    if "isOwner" in row and row["isOwner"].lower() == "false":
        return False            # preinstalled app is on the owner user (0)
    u = row.get("user")
    if u is not None:
        if u.endswith("*"):
            if not app.user.startswith(u[:-1]):
                return False
        elif u != app.user:
            return False
    if "seinfo" in row and row["seinfo"] != app.seinfo:
        return False
    if "name" in row and not _name_matches(app.package, row["name"]):
        return False
    if "isPrivApp" in row and (row["isPrivApp"].lower() == "true") != app.is_priv:
        return False
    if "minTargetSdkVersion" in row:
        try:
            if app.target_sdk < int(row["minTargetSdkVersion"]):
                return False
        except ValueError:
            pass
    return True


def _specificity(row: dict) -> tuple:
    """AOSP-like precedence key: a row that constrains more / more specifically wins."""
    def rank(val: Optional[str]) -> int:
        if val is None:
            return 0
        return 1 if val.endswith("*") else 2        # prefix < exact
    try:
        min_sdk = int(row.get("minTargetSdkVersion", "0"))
    except ValueError:
        min_sdk = 0
    return (
        rank(row.get("user")),
        1 if "seinfo" in row else 0,
        rank(row.get("name")),
        1 if "isPrivApp" in row else 0,
        min_sdk,
    )


def resolve_app_domain(app: AppInfo, seapp_rows: list[dict]) -> Optional[str]:
    """The domain Android would assign `app`, or None if no row matches."""
    best_row: Optional[dict] = None
    best_key = None
    for row in seapp_rows:
        if "domain" not in row or not _row_matches(row, app):
            continue
        key = _specificity(row)
        if best_key is None or key > best_key:
            best_key, best_row = key, row
    return best_row["domain"] if best_row else None


# --------------------------------------------------------------------------- #
# Building the index
# --------------------------------------------------------------------------- #

def _apk_paths(inodes) -> list[str]:
    """Preinstalled APK device paths (under an app/ or priv-app/ dir), excluding overlays."""
    out = []
    for path, meta in inodes.meta.items():
        if (path.endswith(".apk") and not meta.is_dir and _APP_DIR_RE.search(path)
                and "/overlay/" not in path):
            out.append(path)
    return sorted(out)


def build_app_domain_index(files, inodes, contexts) -> AppDomainIndex:
    """Map every preinstalled APK to its app domain via seapp_contexts matching.

    Best-effort: if androguard is unavailable the index is empty (the locator then
    keeps its honest "an installed APK" fallback). Each APK is parsed once.
    """
    idx = AppDomainIndex()
    try:
        from androguard.core.apk import APK  # noqa: F401
    except Exception:
        return idx
    quiet_androguard()

    signers = load_seinfo_signers(files)
    seapp = contexts.seapp
    scratch = tempfile.mkdtemp(prefix="sesurface-apk-")
    dst = os.path.join(scratch, "a.apk")
    try:
        for path in _apk_paths(inodes):
            if not files.extract_to(path, dst):
                continue
            info = _parse_apk(path, dst, signers)
            if info is None:
                continue
            dom = resolve_app_domain(info, seapp)
            if not dom:
                continue
            info.domain = dom
            idx.apps[path] = info
            idx.by_domain.setdefault(dom, []).append(path)
    finally:
        try:
            os.remove(dst)
            os.rmdir(scratch)
        except OSError:
            pass
    for paths in idx.by_domain.values():
        paths.sort()
    return idx


def _parse_apk(device_path: str, host: str, signers: dict[str, str]) -> Optional[AppInfo]:
    from androguard.core.apk import APK
    try:
        a = APK(host)
    except Exception:
        return None
    pkg = a.get_package() or ""
    if not pkg:
        return None
    shared = a.get_attribute_value("manifest", "sharedUserId")
    user = _SHARED_UID_USER.get(shared or "", "_app")
    seinfo = "default"
    try:
        certs = a.get_certificates()
        if certs:
            seinfo = signers.get(certs[0].dump().hex().upper(), "default")
    except Exception:
        pass
    try:
        tsdk = int(a.get_target_sdk_version() or 0)
    except (TypeError, ValueError):
        tsdk = 0
    return AppInfo(path=device_path, package=pkg, user=user, seinfo=seinfo,
                   is_priv="/priv-app/" in device_path, target_sdk=tsdk)
