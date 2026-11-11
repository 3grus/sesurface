# sesurface

**Enumerate the object surface an Android SELinux subject can reach — exhaustively and traceably — from an unpacked firmware image.**

Given an unpacked Android firmware image and a *subject* (an SELinux domain such as
`untrusted_app` or `hal_camera_default`), sesurface answers one question:

> If a process in this domain is compromised, what objects can it touch, and what could it pivot to?

It is a **static** tool: it reads the image, never runs the device. Its output is
designed to be *audited* — every reachable object is reported together with the
evidence behind each access decision, so a reviewer can check accuracy later.

The ultimate goal (a deferred pass) is to take each reachable object and attribute
it to the **code** that handles it — an APK, a system binary, a `.so`, a kernel
module, or the kernel itself — and point ghidra/jadx at exactly the right place.
This initial version produces the accurate surface map and the object→code index
that that pass will consume.

---

## The model, in plain English

SELinux and Android stack **four independent gates** between a subject and an
object. An access succeeds only if **every** gate allows it:

| Gate | Plain-English question | Decided by |
|---|---|---|
| **1. SELinux TE** | Is there an `allow` rule letting this domain do this to this type? | The compiled SELinux policy (type-enforcement rules, plus `ioctl` command whitelists). |
| **2. MLS** | Are the security *categories* compatible? (This is what stops app A reading app B's data even though both are the `app_data_file` type.) | Category constraints in the policy. |
| **3. DAC** | Do the classic Unix owner/group/mode bits — on the whole path — permit it? | File ownership and permissions, read from the image itself. |
| **4. In-code** | Does the server's own code accept the request (a permission check, a uid check, AppOps)? | Bytecode inside the service. **A static tool can only *flag* this, not decide it** — it is the main reason "can reach a service" ≠ "owns the device". |

Modelling too few gates **over-reports** (claims accesses that DAC or MLS actually
block). Missing objects or pivot paths **under-reports**. sesurface runs all four and
records each verdict with its evidence, so a finding reads like:

```
untrusted_app -> /dev/kgsl-3d0  (gpu_device, chr_file)
  TE     allow  : allow appdomain gpu_device:chr_file { read write open ioctl map }
  MLS    n/a    : gpu_device is mlstrustedobject
  DAC    allow  : 0666 system:system  (other rw)   [ueventd.rc + file_contexts]
  in-code n/a   : kernel driver, no userspace caller check
  backing: confirmed (device node) -> kgsl driver  [kernel attack surface]
```

Each finding also carries a **backing tier** — `confirmed` (a real artifact in the
image), `predicted` (config the tool can read will create it at runtime), or
`policy-only` (the rule exists but nothing is labelled that type here) — and, where
relevant, a **pivot**: `BECOMES` (run code as a new domain, no further bug needed)
or `ATTACKS` (feed input to a domain; a bug there would escalate).

## What a static, image-only analysis cannot see

sesurface is explicit about its blind spots and prints them with every report.
Briefly: anonymous binder objects and callback tokens (handles passed inside
transactions, created at runtime in code), abstract-namespace sockets (`@name`, no
filesystem entry), TCP/UDP localhost listeners, the in-code permission checks
themselves (that needs the deferred jadx pass), the live contents of `/data`,
runtime-registered services and lazy-HAL state, third-party apps and concrete
appIds, runtime permission/AppOps/role grants, and anything the bootloader appends
to the kernel command line. The report explains each one.

## Install

sesurface runs in a **uv virtual environment on Ubuntu 24.04 / 26.04**. The SELinux
toolkit it depends on (`setools`, `libselinux`, `secilc`) is not on PyPI — it comes
from `apt`, and the venv is created with `--system-site-packages` so those bindings
are importable.

```bash
scripts/bootstrap-ubuntu.sh      # apt-installs system deps + creates the venv + uv sync
uv run sesurface doctor            # confirm everything is present
```

`sesurface doctor` lists every external tool/binding, says what each enables, and —
for anything missing — names exactly which analysis layer degrades. Run it first.

## Usage

```bash
# Build and cache the source-independent image + policy model (done once per image).
uv run sesurface build-image -r /path/to/unpacked_image

# Enumerate the surface for one or more source domains (reuses the cache).
uv run sesurface reach -r /path/to/unpacked_image -s untrusted_app \
    --report out/untrusted_app.md --json out/untrusted_app.json

# Later: map a finished reach report to the code that handles each object.
uv run sesurface locate --json out/untrusted_app.json
```

The expensive, source-independent work (reconstructing the image and assembling the
policy) is cached on disk keyed by an image fingerprint, so re-running with a
different `-s` domain is cheap.

## How it is built

The pipeline is split into stages so the source-independent parts are computed once
and cached. See `sesurface/types.py` for the shared data model (read that first), then:

- `sesurface/model/` — the **image model** (partitions, true inode metadata, context
  files, build props, init `.rc`, ueventd, VINTF). Independent of any subject.
- `sesurface/policy/` — **policy assembly** (precompiled-vs-compile decision) and the
  setools adapter.
- `sesurface/subject.py` — resolve the subject's identity (domain → uid/gids/caps/MLS;
  and the reverse, an APK or binary → its domain).
- `sesurface/gates/` — the four gates, and the engine that ANDs them per object.
- `sesurface/backing.py`, `pivot.py`, `locate.py` — object resolution, pivots, and the
  bridge to the deferred code-attribution pass.
- `sesurface/report.py`, `cache.py` — the traceable report and the JSON cache.

This project is a clean re-implementation. It ports the genuinely-robust primitives
from the sibling `sepolmap`/`appmap` tree (the setools adapter, the context-file
parser, the inode-index structure), re-documented for readability, and fixes the
correctness bugs catalogued in the "Blast Radius Field Guide" review.
