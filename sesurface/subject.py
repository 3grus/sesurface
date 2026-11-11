"""Resolve a source domain to a Subject -- who the attacker is after compromise.

The gates need more than a domain name. The MLS gate needs to know how the domain's
categories are assigned (`levelFrom`) and whether it is an `mlstrustedsubject`; the
TE gate needs to know whether the domain is permissive (gate open); the DAC gate
needs the uid class and groups. This module fills those in from the policy and the
seapp_contexts file.

What is and is not resolvable statically (guide ch. 5, 7, 21):
  * domain, permissive flag, mlstrustedsubject flag, and an app domain's levelFrom:
    fully static -- read here.
  * an app's concrete appId and its MLS categories: runtime-only -- we reason
    symbolically (own / another app / same-user), which is enough to decide the gate.
  * a native daemon's exact uid/gids/caps: come from its init .rc service block.
    Wiring that in is a later enrichment; until then those fields are left unknown
    for native domains rather than guessed.
"""

from __future__ import annotations

from typing import Optional

from .model.aids import AidDb
from .model.contexts import ContextDB
from .model.initrc import DomainServiceMap, InitService
from .policy.policy import Policy
from .types import LevelFrom, Subject, UidClass

# A few domains whose uid class is fixed and worth naming precisely.
_UID_CLASS_BY_DOMAIN = {
    "system_app": UidClass.SYSTEM,
    "system_server": UidClass.SYSTEM,
    "platform_app": UidClass.APP,
    "priv_app": UidClass.APP,
    "isolated_app": UidClass.ISOLATED,
    "ephemeral_app": UidClass.APP,
}


def resolve_subject(policy: Policy, contexts: ContextDB, domain: str,
                    dsmap: Optional[DomainServiceMap] = None,
                    aids: Optional[AidDb] = None) -> Subject:
    """Build the Subject for `domain` from the policy, seapp_contexts and init `.rc`.

    `dsmap`/`aids` (optional) let a native-daemon domain resolve its concrete
    uid/gids/caps from the init service that runs as it. Without them the native case
    falls back to "unknown", exactly as before, so callers that only have the policy
    still work.
    """
    prov: list[str] = []

    is_app = domain in policy.expand("appdomain")
    is_trusted = domain in policy.expand("mlstrustedsubject")
    is_permissive = domain in policy.permissive_domains()

    if is_permissive:
        prov.append("domain is PERMISSIVE: the SELinux (TE) gate is open for it")
    if is_trusted:
        prov.append("domain is mlstrustedsubject: exempt from MLS category checks")

    uid: Optional[int] = None
    gids: tuple[int, ...] = ()
    caps: frozenset[str] = frozenset()

    # Uid class.
    if domain in _UID_CLASS_BY_DOMAIN:
        uid_class = _UID_CLASS_BY_DOMAIN[domain]
    elif is_app:
        uid_class = UidClass.APP
    else:
        # Native/unknown domain: try to resolve its identity from init `.rc`.
        native = _native_identity(domain, dsmap, aids, prov) if dsmap else None
        if native is not None:
            uid_class, uid, gids, caps = native
        else:
            uid_class = UidClass.UNKNOWN
            prov.append("native/unknown domain: no init .rc service maps to it "
                        "(it may be started by another domain, or labelled via a "
                        "runtime path); uid/gids/caps left unknown")

    # MLS levelFrom and own-data type, from the seapp_contexts row(s) for this domain.
    level_from = LevelFrom.NONE
    data_type: Optional[str] = None
    seapp_match = _seapp_level_from(contexts, domain)
    if seapp_match is not None:
        level_from, row_desc, data_type = seapp_match
        prov.append(f"seapp_contexts: levelFrom={level_from.value} "
                    f"type={data_type or '?'} ({row_desc})")
    elif is_app:
        prov.append("app domain with no seapp levelFrom found: assuming no MLS "
                    "category isolation (worst case)")

    # Apps have no capabilities (zygote clears them) and no fixed supplementary gids
    # we can read without the install database, so for app subjects uid/gids/caps
    # stay empty; native daemons got theirs from the `.rc` above.

    return Subject(
        domain=domain,
        uid_class=uid_class,
        uid=uid,
        gids=gids,
        level_from=level_from,
        data_type=data_type,
        is_mls_trusted=is_trusted,
        is_permissive=is_permissive,
        caps=caps,
        provenance=prov,
    )


def _native_identity(
    domain: str, dsmap: DomainServiceMap, aids: Optional[AidDb], prov: list[str],
) -> Optional[tuple[UidClass, Optional[int], tuple[int, ...], frozenset[str]]]:
    """Resolve a native domain's uid/gids/caps from its init service block.

    Returns (uid_class, uid, gids, caps) or None if no service maps to the domain.
    When several services share a domain (e.g. a 32- and 64-bit HAL) they carry the
    same identity; we take the first and note it.
    """
    services = dsmap.services_for(domain)
    if not services:
        return None
    svc: InitService = services[0]

    # Several services can share one domain (a 32- and 64-bit HAL, or two provider
    # versions). If they disagree on uid/groups, only one actually runs on this
    # device and we cannot tell which statically, so we flag it rather than hide it.
    others = [s for s in services[1:]
              if (s.user, tuple(s.groups)) != (svc.user, tuple(svc.groups))]
    if others:
        alt = "; ".join(f"'{s.name}' (user={s.user})" for s in others)
        prov.append(f"NOTE: {len(services)} init services map to this domain with "
                    f"differing identity; using '{svc.name}'. Alternatives: {alt}")

    uid = aids.uid(svc.user) if aids else None
    gids: tuple[int, ...] = ()
    if aids:
        resolved = [aids.gid(g) for g in svc.groups]
        gids = tuple(g for g in resolved if g is not None)
    # init capabilities are named like SYS_NICE / NET_ADMIN; we store them lower-cased
    # to match the SELinux `capability` perm names the in-code/DAC reasoning uses.
    caps = frozenset(c.lower() for c in svc.capabilities)

    # uid 0 is root; uid 1000 is the system server's uid; anything else with a fixed
    # AID is a native daemon. This classification drives the DAC group logic.
    if uid == 0:
        uid_class = UidClass.ROOT
    elif uid == 1000:
        uid_class = UidClass.SYSTEM
    elif uid is not None:
        uid_class = UidClass.NATIVE
    else:
        uid_class = UidClass.UNKNOWN

    grp = " ".join(svc.groups) or "(none)"
    cap = " ".join(svc.capabilities) or "(none)"
    prov.append(f"init service '{svc.name}' ({svc.source}): user={svc.user}"
                f"(uid={uid}) groups=[{grp}] caps=[{cap}]")
    if svc.seclabel is None:
        prov.append(f"  domain derived from exec {svc.exec_path} via a process "
                    f"type_transition (no explicit seclabel in the .rc)")
    return uid_class, uid, gids, caps


def _seapp_level_from(contexts: ContextDB,
                      domain: str) -> Optional[tuple[LevelFrom, str, Optional[str]]]:
    """Find levelFrom, a describing selector, and the own-data type for a domain.

    Several rows may map to one domain (different minTargetSdkVersion tiers). They
    usually share a levelFrom; if they differ we take the most isolating one
    (all > app > user > none) and note it, because that is the safe assumption when
    we do not know the app's target SDK. The `type=` output (the data-dir type) is
    taken from the same winning row.
    """
    order = {LevelFrom.ALL: 3, LevelFrom.APP: 2, LevelFrom.USER: 1, LevelFrom.NONE: 0}
    best: Optional[LevelFrom] = None
    desc = ""
    data_type: Optional[str] = None
    for row in contexts.seapp:
        if row.get("domain") != domain:
            continue
        lf_raw = row.get("levelFrom", "none").lower()
        try:
            lf = LevelFrom(lf_raw)
        except ValueError:
            lf = LevelFrom.NONE
        if best is None or order[lf] > order[best]:
            best = lf
            data_type = row.get("type")
            sel = " ".join(f"{k}={v}" for k, v in row.items()
                           if k in ("user", "seinfo", "isPrivApp", "minTargetSdkVersion"))
            desc = sel or "matched"
    return (best, desc, data_type) if best is not None else None
