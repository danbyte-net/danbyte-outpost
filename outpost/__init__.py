"""Danbyte Outpost — remote monitoring agent.

Runs checks at a site with no direct path to the core and reports back over
outbound HTTPS (or is driven in over SSH). Ships the *same* ``danbyte_checks``
engine the core runs, so results never drift.

``PROTOCOL_VERSION`` is the wire contract with Danbyte. It is bumped **only** on
a breaking change; the agent and the core are versioned independently so a site
need not upgrade in lockstep with Danbyte (see docs/COMPATIBILITY.md in the
danbyte-outpost repo).
"""

__version__ = "0.2.0"
PROTOCOL_VERSION = 1
