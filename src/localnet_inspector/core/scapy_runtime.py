from __future__ import annotations

import os
from pathlib import Path


def configure_scapy_cache_home() -> None:
    """Ensure Scapy uses an app-owned writable cache folder."""
    home = Path.home()
    if os.name == "posix" and "darwin" in os.uname().sysname.lower():
        target = home / "Library" / "Caches" / "LocalnetInspector"
    else:
        target = home / ".cache" / "localnet-inspector"

    try:
        target.mkdir(parents=True, exist_ok=True)
        os.environ["XDG_CACHE_HOME"] = str(target)
    except Exception:
        # Fallback to a local directory if the home cache path is not writable.
        fallback = Path("/tmp/localnet-inspector-cache")
        fallback.mkdir(parents=True, exist_ok=True)
        os.environ["XDG_CACHE_HOME"] = str(fallback)
