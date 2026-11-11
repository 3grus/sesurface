"""Stage B -- the SELinux policy.

Two concerns live here:

  * `assemble.py` decides *which* policy the device actually loads (a precompiled
    binary, or one compiled on-device from split CIL) and reproduces it on the host.
  * `policy.py` is the single module that touches the `setools` library. Everything
    version-sensitive about setools is contained here; the rest of sesurface only ever
    sees the plain value objects this module returns.
"""
