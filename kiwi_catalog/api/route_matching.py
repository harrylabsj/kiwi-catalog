"""Pure route-template matching helpers used by both API stacks.

This module intentionally owns no route table or handler policy. Keeping the
matcher isolated makes the app facade easier to split without changing the
fallback/FastAPI behavior.
"""

from __future__ import annotations

import re


def match_path(template: str, path: str) -> dict[str, str] | None:
    """Return path parameters when *path* matches a route template."""
    parts = template.split("/")
    regex_parts = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            param_name = part[1:-1]
            regex_parts.append(f"(?P<{param_name}>[^/]+)")
        else:
            regex_parts.append(re.escape(part))
    match = re.match("^" + "/".join(regex_parts) + "$", path)
    return match.groupdict() if match else None
