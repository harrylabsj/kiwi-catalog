"""Agent Catalog — discovery-plane persistence and public serialization.

The catalog is a read-optimised index of discoverable commerce agents.
It does NOT hold authoritative identity, runtime state, or private
merchant metadata.  See docs/shopping-cli-a2a-upgrade-design-v1.2.1.md.
"""

from __future__ import annotations
