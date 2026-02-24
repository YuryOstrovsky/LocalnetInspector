from __future__ import annotations

from datetime import datetime
from typing import Callable, Iterable, Optional, Sequence

from .fingerprints import guess_os_from_dhcp_param_list, normalize_param_list
from .models import DeviceRecord
from .scapy_runtime import configure_scapy_cache_home


def _extract_dhcp_option(options: Iterable[tuple], key: str):
    for opt in options:
        if isinstance(opt, tuple) and len(opt) == 2 and opt[0] == key:
            return opt[1]
    return None


def _normalize_msg_type(msg_type) -> str | None:
    if isinstance(msg_type, bytes):
        try:
            return msg_type.decode(errors="ignore").strip().lower()
        except Exception:
            return None
    if isinstance(msg_type, str):
        return msg_type.strip().lower()
    if isinstance(msg_type, int):
        mapping = {
            1: "discover",
            2: "offer",
            3: "request",
            4: "decline",
            5: "ack",
            6: "nak",
            7: "release",
            8: "inform",
        }
        return mapping.get(msg_type)
    return None


def _as_int_list(values: Sequence[int] | bytes | bytearray | tuple | list | None) -> list[int]:
    if values is None:
        return []
    if isinstance(values, (bytes, bytearray)):
        return [int(v) for v in values]
    if isinstance(values, (list, tuple)):
        out: list[int] = []
        for v in values:
            try:
                out.append(int(v))
            except Exception:
                continue
        return out
    return []


def listen_dhcp(on_device: Callable[[DeviceRecord], None], iface: Optional[str] = None) -> None:
    configure_scapy_cache_home()
    from scapy.all import BOOTP, DHCP, sniff  # type: ignore

    def process(pkt):
        if DHCP not in pkt or BOOTP not in pkt:
            return

        dhcp_options = pkt[DHCP].options
        msg_type = _normalize_msg_type(_extract_dhcp_option(dhcp_options, "message-type"))
        if msg_type not in {"discover", "request", "inform"}:
            return

        param_req_list = _as_int_list(_extract_dhcp_option(dhcp_options, "param_req_list"))
        if not param_req_list:
            return

        mac = pkt[BOOTP].chaddr[:6].hex(":").lower()
        ip = pkt[BOOTP].ciaddr or "0.0.0.0"
        hostname = _extract_dhcp_option(dhcp_options, "hostname")
        fingerprint = normalize_param_list(param_req_list)
        os_guess = guess_os_from_dhcp_param_list(param_req_list)

        now = datetime.utcnow()
        on_device(
            DeviceRecord(
                ip=ip,
                mac=mac,
                hostname=hostname.decode(errors="ignore") if isinstance(hostname, bytes) else hostname,
                vendor=None,
                first_seen=now,
                last_seen=now,
                source="dhcp",
                dhcp_fingerprint=fingerprint,
                os_guess=os_guess,
            )
        )

    sniff(filter="udp and (port 67 or port 68)", prn=process, store=False, iface=iface)
