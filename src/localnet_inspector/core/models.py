from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class DeviceRecord:
    ip: str
    mac: str
    hostname: Optional[str]
    vendor: Optional[str]
    first_seen: datetime
    last_seen: datetime
    source: str
    dhcp_fingerprint: Optional[str] = None
    os_guess: Optional[str] = None
