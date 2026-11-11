"""Stage D -- the four access gates and the engine that combines them.

Each module evaluates one gate for a candidate object and returns a `GateVerdict`
(allow / deny / n-a / unknown) with the evidence behind it. `combine.py` runs them
all and ANDs the result into a `Finding`. The guiding rule: an access succeeds only
if every applicable gate allows it, and a gate we cannot decide statically is
reported as `unknown` (surfaced, never silently dropped).
"""
