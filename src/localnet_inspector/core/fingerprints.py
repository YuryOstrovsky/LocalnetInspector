from __future__ import annotations

from typing import Iterable

# Very small starter map. Extend this as you capture more fingerprints.
DHCP_PARAM_LIST_OS_MAP: dict[str, str] = {
    "1,3,6,15,119,252": "Windows (likely modern)",
    "1,3,6,15,26,28,51,58,59": "Linux (common dhclient pattern)",
    "1,3,6,15,119,252,95,44,46": "macOS / iOS (possible)",
    "1,121,3,6,15,26,28,51,58,59": "Android / embedded Linux (possible)",
    "1,3,6,12,15,28,51,58,59": "IoT / embedded stack (possible)",
}


def normalize_param_list(values: Iterable[int]) -> str:
    return ",".join(str(v) for v in values)


def guess_os_from_dhcp_param_list(values: Iterable[int]) -> str | None:
    key = normalize_param_list(values)
    if key in DHCP_PARAM_LIST_OS_MAP:
        return DHCP_PARAM_LIST_OS_MAP[key]

    # Fallback heuristics
    seq = set(values)
    if {119, 252}.issubset(seq):
        return "Likely Windows/macOS family"
    if {58, 59}.issubset(seq):
        return "Likely Linux/Unix DHCP client"
    return None
