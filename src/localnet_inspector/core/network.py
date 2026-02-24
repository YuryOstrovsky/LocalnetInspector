from __future__ import annotations

import ipaddress
import socket
import subprocess
from datetime import datetime
from typing import Optional

import psutil

from .models import DeviceRecord
from .scapy_runtime import configure_scapy_cache_home


def _default_route_iface() -> str | None:
    try:
        proc = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        return None
    return None


def detect_primary_network() -> tuple[str, str | None]:
    default_iface = _default_route_iface()
    iface_addrs = psutil.net_if_addrs()

    if default_iface and default_iface in iface_addrs:
        addrs = iface_addrs[default_iface]
        ipv4 = next((a for a in addrs if a.family == socket.AF_INET), None)
        if ipv4 and ipv4.netmask:
            try:
                network = ipaddress.IPv4Network(f"{ipv4.address}/{ipv4.netmask}", strict=False)
                if network.prefixlen <= 30:
                    return str(network), default_iface
            except ValueError:
                pass

    for iface_name, addrs in psutil.net_if_addrs().items():
        if iface_name.startswith("lo") or iface_name.startswith("utun"):
            continue
        if iface_name.startswith("awdl") or iface_name.startswith("llw"):
            continue
        ipv4 = next((a for a in addrs if a.family == socket.AF_INET), None)
        if not ipv4 or not ipv4.netmask:
            continue

        try:
            network = ipaddress.IPv4Network(f"{ipv4.address}/{ipv4.netmask}", strict=False)
            if network.prefixlen <= 30:
                return str(network), iface_name
        except ValueError:
            continue

    return "192.168.1.0/24", None


def detect_primary_subnet() -> str:
    subnet, _ = detect_primary_network()
    return subnet


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def active_arp_scan(subnet: str, timeout: int = 2, iface: str | None = None) -> list[DeviceRecord]:
    configure_scapy_cache_home()
    from scapy.all import ARP, Ether, srp  # type: ignore

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(packet, timeout=timeout, verbose=False, iface=iface)

    now = datetime.utcnow()
    devices: list[DeviceRecord] = []
    for _, recv in answered:
        ip = recv.psrc
        mac = recv.hwsrc.lower()
        devices.append(
            DeviceRecord(
                ip=ip,
                mac=mac,
                hostname=reverse_dns(ip),
                vendor=None,
                first_seen=now,
                last_seen=now,
                source="arp",
            )
        )

    return devices
