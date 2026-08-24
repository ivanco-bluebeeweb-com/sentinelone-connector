"""SentinelOne Connector entrypoint."""
from __future__ import annotations

import handlers_connection  # noqa: F401
import handlers_threats  # noqa: F401
import handlers_agents  # noqa: F401
import handlers_exclusions  # noqa: F401
import handlers_deep_visibility  # noqa: F401
import handlers_audit  # noqa: F401
import panels  # noqa: F401
import panels_center  # noqa: F401
import panels_settings  # noqa: F401
from app import ext

extension = ext
