"""Curated, deterministic proof-of-concept exploits for HALO.

Each module here is a self-contained, dependency-free (stdlib socket) exploit for
a *specific, known* vulnerable service — the kind a 12B cannot reliably author
from a blank page but which is 100% deterministic once written correctly. The
full source of each module is shipped verbatim as the `code` string that the
sandbox `run_exploit` runner executes, so what the test suite exercises is byte
-for-byte what fires against a target. See ``poc_library.select_poc``.
"""
