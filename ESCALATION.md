# Reading the surface: from a compromised domain to disabling SELinux

Working notes for interpreting sesurface output. The tool enumerates reachable
surface; this is how to turn that into an escalation judgement.

## The question the output answers

`reach -s <domain>` lists every object a compromised process in `<domain>` can
touch, and every domain it can pivot to. An access is real only if **all four
gates** allow it: SELinux type-enforcement (the allow rule), MLS categories, DAC
(unix bits on the whole path), and the server's own in-code check. The tool decides
the first three; the fourth (COD) it can only *flag* — and that flag is the
vulnerability surface.

Three views, used together:

- `reach` — forward: one domain → everything it reaches.
- `who-can-touch <path>` — inverse: one object → every domain that reaches it.
- `crown-jewels` — the targets: who holds a SELinux-disable primitive, and (with
  `--from <domain>`) whether your attacker actually reaches them.

## What "disable SELinux" actually requires

There are only a few end states, and they are the crown jewels:

1. **Kernel code execution** — flip `enforcing` in kernel memory directly. MAC is
   irrelevant in ring 0. Reached through a bug in a driver you can `ioctl`.
2. **A userspace domain with `security setenforce` / `load_policy`** plus write to
   `/sys/fs/selinux/enforce` or `/load`. In practice only `init`/`vendor_init` hold
   these, so this is only ever the *end* of a BECOMES chain into init-like context.
3. **`capability sys_module` / `sys_rawio`, or `capability2 mac_admin`** — a
   kernel-code or MAC-bypass primitive in a domain you can become.

On a compliant `user` build, route 1 dominates: no app-reachable userspace domain
holds `setenforce`, so the realistic path is kernel RCE via a reachable driver.
`crown-jewels --from untrusted_app` returning "no reachable holder" confirms that —
it is a result, not a dead end.

## Reading reach output for escalation

Work the pivots first; they are ranked (0 = most severe, see `pivot.py`):

- **rank 5 — BECOMES**: a free domain change, no bug needed (an exec-transition, or
  a file/property you control that a privileged domain executes or loads as code). A
  BECOMES into non-app context is a direct rung up.
- **rank 15 — ATTACKS → kernel**: an `ioctl` into a device node. A bug here is
  route 1. The `xperms` on the finding are the exact ioctl commands allowed — the
  precise entry points. `kerneldrv` attributes each known node to its handler
  symbol, source file and `_IOC` table, confirmed against the kernel image.
- **rank 25 — ATTACKS → HAL**, **rank 45 — ATTACKS → service**: a bug in that
  server's code would escalate.

Each pivot carries a `lockdown` (the single rule to remove to kill the edge) and
`code` (the `.apk`/`.so`/`.jar`/handler to open). Findings carry `backing.tier` —
trust `confirmed` (a real artifact in the image); treat `policy-only` as latent.

## Which reachable thing pivots to kernel execution

A finding is a kernel entry point when its class is `chr_file`/`blk_file`, it
carries `xperms` (ioctl allowed), and `kerneldrv` attributes it to a kernel handler.
Rank those by:

- **reachability** — directly reachable from the attacker (rank-15) over
  needs-another-hop;
- **breadth** — a driver shared across the OEM/chipset lineup over a one-device node
  (oempocalypse's lens: one bug, many devices);
- **primitive quality** — page-level / memory-write ioctls over narrow ones.

That ordered list is the kernel-bug-hunting worklist. Static analysis gives you the
reachable surface and its ioctl commands; it cannot find the bug — that is the
Ghidra hand-off.

## The userspace route

Chase BECOMES/ATTACKS toward a privileged domain. `reach` closes BECOMES to depth 3;
where it stops, re-run `reach` on the reached domain to extend the chain. You want a
chain that ends in a domain `crown-jewels` lists as a holder of route 2/3. Confirm
with `who-can-touch /sys/fs/selinux/enforce` — and cross-check the
`security:setenforce` holders in `crown-jewels`, because writing the toggle also
needs that permission (the file write alone is necessary, not sufficient).

## Turning this into a ranked audit list

The in-code (COD) gate is UNKNOWN until `attribute` resolves it; its ledger marks
each target gated / ungated / needs-review. The leads worth a human are: a target
reachable from the attacker, with a scary `to_domain` or a kernel ioctl, where COD
is **ungated** or **needs-review** — i.e. nothing but the server's own (absent)
check stands between you and it. `attribute`'s `code_refs` names the file to open.

Rough priority:

```
privilege(end state) × 1/hops × narrowness(COD) × breadth × confirmed-backing
```

`privilege(end state)` is which of the three routes the chain reaches; the rest are
fields the tool already emits (`rank`, the COD ledger, `backing.tier`). `breadth` is
the one judgement you add by hand.

## Limits to keep honest

- COD flags where to look; it does not prove a bug exists.
- Static analysis cannot see the kernel vulnerability, only the reachable entry
  points and their ioctl surface.
- `crown-jewels` enumerates the file primitives and the class/capability primitives;
  it does not model a specific kernel memory-write bug — that is the thing you go
  find.
- Runtime-only paths give *predicted* labels; abstract-namespace sockets, localhost
  listeners and runtime binder tokens are invisible (documented blind spots).
