"""Work around snowflake-connector-python failing under Microsoft Store Python.

Import this module before opening a Snowflake connection. The connector reads
sys.executable during authentication to collect interpreter telemetry, which fails
on the Store's zero-length alias stub. The value is telemetry only, so returning an
empty version is harmless.
"""

from __future__ import annotations

import platform
import sys


def apply() -> bool:
    """Neutralise platform.libc_ver on Store Python. True if patched."""
    executable = sys.executable or ""
    if "WindowsApps" not in executable:
        return False
    try:
        with open(executable, "rb"):
            return False  # readable, so the bug does not apply
    except OSError:
        pass
    # Replace the probe with a constant, which is all the telemetry needs.
    platform.libc_ver = lambda *args, **kwargs: ("", "")
    return True


# Applied on import, so importing this module before connecting is enough.
PATCHED = apply()
