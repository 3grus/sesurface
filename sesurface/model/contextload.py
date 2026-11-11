"""Load every `*_contexts` / `mac_permissions` file from all partitions.

The split context files live on several partitions (`plat_` on system, `vendor_`
on vendor, plus `system_ext_`, `product_`, `odm_`). The old code loaded only the
`plat_`/`vendor_` variants and missed the rest (a Chapter 22 finding), so OEM
services and properties came back unresolved. Here we load the full set, in
partition load order, so the precedence in `contexts.ContextDB` is correct.
"""

from __future__ import annotations

from .contexts import ContextDB
from .extract import ImageFiles

# (device path, loader-method name). Ordered by partition so that, after loading,
# the ContextDB's finalize() applies the right file_contexts precedence. We list
# every partition variant of every context file.
_CONTEXT_FILES: list[tuple[str, str]] = []


def _add(method: str, *paths: str) -> None:
    for p in paths:
        _CONTEXT_FILES.append((p, method))


# file_contexts (all partitions, plat first).
_add("load_file_contexts",
     "/system/etc/selinux/plat_file_contexts",
     "/system_ext/etc/selinux/system_ext_file_contexts",
     "/product/etc/selinux/product_file_contexts",
     "/vendor/etc/selinux/vendor_file_contexts",
     "/odm/etc/selinux/odm_file_contexts")

# service_contexts (binder), hwservice_contexts (hwbinder), vndservice_contexts.
_add("load_service_contexts",
     "/system/etc/selinux/plat_service_contexts",
     "/system_ext/etc/selinux/system_ext_service_contexts",
     "/product/etc/selinux/product_service_contexts",
     "/vendor/etc/selinux/vendor_service_contexts",
     "/odm/etc/selinux/odm_service_contexts",
     "/system/etc/selinux/plat_hwservice_contexts",
     "/vendor/etc/selinux/vendor_hwservice_contexts",
     "/odm/etc/selinux/odm_hwservice_contexts",
     "/vendor/etc/selinux/vndservice_contexts")

# property_contexts (all partitions).
_add("load_property_contexts",
     "/system/etc/selinux/plat_property_contexts",
     "/system_ext/etc/selinux/system_ext_property_contexts",
     "/product/etc/selinux/product_property_contexts",
     "/vendor/etc/selinux/vendor_property_contexts",
     "/odm/etc/selinux/odm_property_contexts")

# seapp_contexts (all partitions).
_add("load_seapp_contexts",
     "/system/etc/selinux/plat_seapp_contexts",
     "/system_ext/etc/selinux/system_ext_seapp_contexts",
     "/product/etc/selinux/product_seapp_contexts",
     "/vendor/etc/selinux/vendor_seapp_contexts",
     "/odm/etc/selinux/odm_seapp_contexts")


def load_contexts(files: ImageFiles, work_dir: str) -> ContextDB:
    """Parse all present context files into one finalized ContextDB.

    Each file is extracted to `work_dir` and handed to the matching parser. Missing
    files are skipped quietly (not every partition ships every file). `finalize()`
    is called once so file_contexts lookups are device-accurate afterwards.
    """
    import os
    os.makedirs(work_dir, exist_ok=True)
    db = ContextDB()
    for dev_path, method in _CONTEXT_FILES:
        if not files.exists(dev_path):
            continue
        local = os.path.join(work_dir, dev_path.lstrip("/").replace("/", "_"))
        if files.extract_to(dev_path, local):
            getattr(db, method)(local)
    db.finalize()
    return db
