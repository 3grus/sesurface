"""Gate 4: the check inside the server's own code.

SELinux and DAC only decide whether a subject can *reach* a server. Once a binder
transaction (or an intent, or a socket message) arrives, the server's own code
decides whether to act on it -- `Binder.getCallingUid()`, `enforceCallingPermission`,
AppOps. This is the gate a static policy analysis cannot see, and the main reason
"can call system_server" is not "owns the device".

So this module never returns ALLOW/DENY for the cases where the gate is real: it
returns UNKNOWN with a pointer to where the check would be (which the deferred
jadx/ghidra pass resolves). It returns NA for object classes that have no in-code
gate at all (files, devices, properties -- there the kernel, DAC and init are the
whole story). It also encodes the guide's key heuristic: HAL services usually have
*no* caller check, so for them SELinux reachability is effectively real reachability
-- which is exactly why HALs are the prime pivot targets.
"""

from __future__ import annotations

from ..types import Decision, Gate, GateVerdict

# Classes where an in-code gate can exist (a server decides in code).
_SERVER_CLASSES = {"binder", "unix_stream_socket", "unix_dgram_socket"}


def evaluate(setype: str, tclass: str) -> GateVerdict:
    """Annotate the in-code gate for a reachable (type, class)."""
    g = Gate.INCODE

    if tclass not in _SERVER_CLASSES:
        return GateVerdict(g, Decision.NA,
                           f"{tclass} has no in-code caller check (decided by the "
                           f"kernel / DAC / TE)")

    # A binder (or socket) target type names the *server's process domain*.
    if _looks_like_hal(setype):
        return GateVerdict(
            g, Decision.UNKNOWN,
            f"{setype} is a HAL/vendor server: these usually do NOT check the caller "
            f"in code, so SELinux reachability is effectively real reachability "
            f"(prime pivot target). Confirm by decompiling its binary.",
            detail={"where": f"vendor binary serving {setype}", "risk": "high"})

    return GateVerdict(
        g, Decision.UNKNOWN,
        f"reaching {setype} does not mean the call succeeds: its code may enforce a "
        f"permission or uid check. Decompile the host (system_server -> services.jar, "
        f"or the owning daemon binary) and look for getCallingUid / "
        f"enforceCallingPermission on the target method.",
        detail={"where": f"code hosting domain {setype}"})


def _looks_like_hal(setype: str) -> bool:
    """Heuristic: does this domain name look like a HAL or vendor server?"""
    return setype.startswith("hal_") or setype.startswith("vendor_") \
        or setype.endswith("_hal") or setype.endswith("_default")
