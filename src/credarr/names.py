"""The one grammar for a Docker container name or ID used as a path segment.

Names come from configuration, so this is a trust boundary, not formatting.
Matching the wrong container is the failure this product cannot undo.
"""

from __future__ import annotations

import re

CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
