"""sesurface -- enumerate the object surface an Android SELinux subject can reach.

Given an unpacked firmware image and a source subject (an SELinux domain), sesurface
answers: if a process in this domain is compromised, what objects can it touch, and
what could it pivot to? Every finding records all four access gates (SELinux type
enforcement, MLS, DAC, and the in-code check) and the concrete artifact behind each
decision, so the result is exhaustive and auditable.

See the module-level docstrings (start with `sesurface.types`) and the project README
for the full model. The pipeline stages live in `sesurface.model`, `sesurface.policy`,
`sesurface.gates`, and the top-level `subject`, `backing`, `pivot`, `locate`,
`report`, `cache` modules.
"""

__version__ = "0.1.0"
