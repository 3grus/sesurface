"""Parse VINTF manifests -- how each HAL is actually provided on this device.

A HAL interface (e.g. `android.hardware.graphics.mapper::IMapper`) can be served two
ways, and which one decides where its *code* lives:

  * `hwbinder`     -- a standalone daemon registers it with hwservicemanager. Its code
                      is that daemon's binary (resolved by the init/`add`-rule path in
                      the locator). A compromise of a caller reaches it over IPC.
  * `passthrough`  -- there is NO separate process. The caller `dlopen`s an
                      implementation `.so` (`<package>@<ver>-impl*.so` under
                      `/vendor/lib64/hw/`) and runs the HAL code IN ITS OWN ADDRESS
                      SPACE. So "reaching" the HAL is not an IPC hop to another domain;
                      the handling code is a library mapped into the caller, and the
                      thing to open in ghidra is that `.so`.

The VINTF manifest (`/vendor/etc/vintf/manifest.xml` + the fragments under
`/vendor/etc/vintf/manifest/` and the odm/system/system_ext equivalents) is what
declares the transport per HAL. Reading it lets the locator replace a bare
"(in-process HAL)" placeholder with the exact implementing library -- closing the
last gap the init/`add`-rule host resolution cannot reach by construction.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VintfHal:
    """One `<hal>` entry: a package, how it is transported, and its interfaces."""
    package: str                 # e.g. "android.hardware.graphics.mapper".
    transport: str               # "hwbinder" | "passthrough" | "".
    versions: list[str] = field(default_factory=list)      # e.g. ["3.0"].
    interfaces: list[str] = field(default_factory=list)    # e.g. ["IMapper"].
    source: str = ""             # manifest file it came from (provenance).

    @property
    def is_passthrough(self) -> bool:
        return self.transport == "passthrough"


@dataclass
class VintfDb:
    """All HAL declarations across the device's VINTF manifests."""
    hals: list[VintfHal] = field(default_factory=list)
    files_read: list[str] = field(default_factory=list)
    # base fqname "package::IInterface" -> the HAL entry, for interface-name lookup.
    _by_iface: dict[str, VintfHal] = field(default_factory=dict)

    def finalize(self) -> "VintfDb":
        for hal in self.hals:
            for iface in hal.interfaces:
                self._by_iface.setdefault(f"{hal.package}::{iface}", hal)
        return self

    def hal_for_iface(self, base_fqname: str) -> Optional[VintfHal]:
        """Look up a HAL by `package::IInterface` (version-stripped)."""
        return self._by_iface.get(base_fqname)


def parse_vintf(files, inode_index) -> VintfDb:
    """Parse every VINTF manifest xml found on the image into a VintfDb.

    Files are discovered from the inode index (any `.xml` under a `vintf` directory)
    so fragment files and OEM additions are covered without a hard-coded list.
    """
    db = VintfDb()
    xml_paths = sorted(p for p in inode_index.meta
                       if "vintf" in p and p.endswith(".xml"))
    for path in xml_paths:
        text = files.read_text(path)
        if not text:
            continue
        hals = _parse_manifest(text, path)
        if hals:
            db.files_read.append(path)
            db.hals.extend(hals)
    return db.finalize()


def _parse_manifest(text: str, source: str) -> list[VintfHal]:
    """Extract `<hal>` entries from one manifest's XML text.

    Tolerant of a manifest root or a bare `<hal>` fragment, and of the leading XML
    comment blocks these files often carry. Malformed XML yields nothing (reported by
    simply not appearing in files_read) rather than aborting the whole parse.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    # Only device/framework MANIFESTS declare what is provided. Compatibility
    # matrices (`<compatibility-matrix>`) declare what is *required* -- same `<hal>`
    # shape but version RANGES and no transport -- so including them would overwrite a
    # real passthrough entry with a requirement. Skip anything that is not a manifest.
    if root.tag not in ("manifest", "hal"):
        return []

    hal_elems = root.iter("hal") if root.tag != "hal" else [root]
    out: list[VintfHal] = []
    for hal in hal_elems:
        name = _text(hal.find("name"))
        if not name:
            continue
        transport_el = hal.find("transport")
        transport = (_text(transport_el) or "").strip().lower()
        versions = [v for v in (_text(e) for e in hal.findall("version")) if v]
        interfaces = [i for i in
                      (_text(e.find("name")) for e in hal.findall("interface")) if i]
        out.append(VintfHal(package=name, transport=transport, versions=versions,
                            interfaces=interfaces, source=source))
    return out


def _text(el) -> Optional[str]:
    return el.text.strip() if el is not None and el.text else None


def impl_so_for(hal: VintfHal, inode_index, limit: int = 4) -> list[str]:
    """On-device `.so` paths implementing a passthrough HAL.

    Passthrough implementations follow the naming convention
    `<package>@<version>-impl*.so` and live under a `lib*/hw/` directory. We match
    that against the inode index so we return only libraries that actually exist on
    this image.
    """
    out: list[str] = []
    want_prefixes = [f"{hal.package}@{v}-impl" for v in hal.versions] or [f"{hal.package}@"]
    for path in inode_index.meta:
        if "/hw/" not in path or not path.endswith(".so"):
            continue
        base = path.rsplit("/", 1)[1]
        if any(base.startswith(p) for p in want_prefixes):
            out.append(path)
            if len(out) >= limit:
                break
    return sorted(out)
