"""Tests for app-domain resolution: the seapp_contexts matching + seinfo parse.

Image/androguard-independent — the matching logic is pure, driven by hand-built
seapp rows and AppInfo records, so it runs anywhere.
"""

from __future__ import annotations

from sesurface.model.appdomain import (AppInfo, load_seinfo_signers,
                                       resolve_app_domain)

# A representative slice of real AOSP seapp_contexts rows (order as on-device).
_SEAPP = [
    {"user": "_isolated", "domain": "isolated_app", "levelFrom": "user"},
    {"user": "_app", "domain": "untrusted_app", "minTargetSdkVersion": "32"},
    {"user": "_app", "isPrivApp": "true", "domain": "priv_app"},
    {"user": "_app", "seinfo": "platform", "domain": "platform_app"},
    {"user": "_app", "isPrivApp": "true", "name": "com.google.android.gms",
     "domain": "gmscore_app"},
    {"user": "system", "seinfo": "platform", "domain": "system_app"},
    {"user": "bluetooth", "seinfo": "bluetooth", "domain": "bluetooth"},
    {"user": "radio", "seinfo": "platform", "domain": "radio"},
]


def _app(package="com.x", user="_app", seinfo="default", is_priv=False, tsdk=33):
    return AppInfo(path="/system/app/X/X.apk", package=package, user=user,
                   seinfo=seinfo, is_priv=is_priv, target_sdk=tsdk)


def test_plain_user_app():
    assert resolve_app_domain(_app(), _SEAPP) == "untrusted_app"


def test_priv_app_beats_untrusted():
    assert resolve_app_domain(_app(is_priv=True), _SEAPP) == "priv_app"


def test_seinfo_platform_beats_priv():
    # platform-signed app: the seinfo row is more specific than the isPrivApp row.
    assert resolve_app_domain(_app(seinfo="platform", is_priv=True), _SEAPP) \
        == "platform_app"


def test_name_match_wins():
    # GMS is Google-signed (not platform), so the platform_app seinfo row doesn't
    # match; among the rows that do (priv_app, gmscore_app) the name= row is the more
    # specific and wins.
    got = resolve_app_domain(
        _app(package="com.google.android.gms", seinfo="default", is_priv=True), _SEAPP)
    assert got == "gmscore_app"


def test_shared_uid_system():
    assert resolve_app_domain(_app(user="system", seinfo="platform"), _SEAPP) \
        == "system_app"


def test_shared_uid_bluetooth():
    assert resolve_app_domain(
        _app(user="bluetooth", seinfo="bluetooth"), _SEAPP) == "bluetooth"


def test_min_target_sdk_excludes():
    # targetSdk 30 < 32, so the untrusted_app row does not match -> nothing here.
    assert resolve_app_domain(_app(tsdk=30), _SEAPP) is None


def test_no_match_returns_none():
    assert resolve_app_domain(_app(user="_nobody"), _SEAPP) is None


class _Files:
    def __init__(self, texts):
        self._t = texts

    def read_text(self, path):
        return self._t.get(path)


def test_seinfo_signer_parse():
    xml = """<policy>
      <signer signature="308204AA">
        <seinfo value="platform"/>
      </signer>
      <signer signature="deadbeef"><seinfo value="media"/></signer>
    </policy>"""
    files = _Files({"/system/etc/selinux/plat_mac_permissions.xml": xml})
    signers = load_seinfo_signers(files)
    assert signers.get("308204AA") == "platform"
    assert signers.get("DEADBEEF") == "media"     # normalised to upper-case
