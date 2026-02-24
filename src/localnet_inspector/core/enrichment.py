from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

COMMON_OUI_PREFIXES: dict[str, str] = {
    "00:1a:11": "Google",
    "00:03:93": "Apple",
    "28:cf:e9": "Apple",
    "3c:07:54": "Apple",
    "40:a6:d9": "Apple",
    "44:65:0d": "Apple",
    "58:55:ca": "Apple",
    "60:03:08": "Apple",
    "64:20:0c": "Apple",
    "70:73:cb": "Apple",
    "7c:6d:62": "Apple",
    "88:66:5a": "Apple",
    "a4:83:e7": "Apple",
    "b8:09:8a": "Apple",
    "bc:52:b7": "Apple",
    "d8:eb:46": "Apple",
    "e0:f8:47": "Apple",
    "f0:18:98": "Apple",
    "00:1b:63": "Samsung",
    "08:37:3d": "Samsung",
    "28:39:26": "Samsung",
    "5c:49:7d": "Samsung",
    "64:b5:c6": "Samsung",
    "fc:a1:3e": "Samsung",
    "00:17:88": "Philips",
    "00:11:32": "Synology",
    "00:1f:3b": "Cisco",
    "00:25:90": "TP-Link",
    "18:fe:34": "Espressif",
    "24:6f:28": "Espressif",
    "30:ae:a4": "Espressif",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
}


@dataclass
class EnrichmentResult:
    hostname: str | None
    vendor: str | None
    device_type: str
    os_guess: str | None
    confidence: float
    open_ports: list[int]
    services: list[str]
    evidence: list[str]
    sources: list[str]


def _clean_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def is_locally_administered_mac(mac: str) -> bool:
    parts = _clean_mac(mac).split(":")
    if not parts or len(parts[0]) != 2:
        return False
    first_octet = int(parts[0], 16)
    return bool(first_octet & 0b00000010)


def lookup_vendor(mac: str) -> str | None:
    normalized = _clean_mac(mac)
    prefix = ":".join(normalized.split(":")[:3])
    if prefix in COMMON_OUI_PREFIXES:
        return COMMON_OUI_PREFIXES[prefix]
    if is_locally_administered_mac(normalized):
        return "Private/Randomized MAC"
    return None


def ssdp_discover(timeout_s: float = 1.5) -> dict[str, dict[str, str]]:
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 1",
            "ST: ssdp:all",
            "",
            "",
        ]
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout_s)
    sock.sendto(msg, ("239.255.255.250", 1900))

    out: dict[str, dict[str, str]] = {}
    while True:
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            break
        except Exception:
            break
        ip = addr[0]
        text = data.decode(errors="ignore")
        headers: dict[str, str] = {}
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        out[ip] = {
            "server": headers.get("server", ""),
            "st": headers.get("st", ""),
            "usn": headers.get("usn", ""),
            "location": headers.get("location", ""),
        }
    sock.close()
    return out


def mdns_discover(timeout_s: float = 2.0) -> dict[str, dict[str, list[str] | str]]:
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except Exception:
        return {}

    service_types = [
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_hap._tcp.local.",
        "_googlecast._tcp.local.",
        "_ipp._tcp.local.",
        "_http._tcp.local.",
        "_smb._tcp.local.",
        "_workstation._tcp.local.",
    ]

    out: dict[str, dict[str, list[str] | str]] = {}

    class Listener(ServiceListener):
        def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            info = zc.get_service_info(service_type, name, timeout=int(timeout_s * 1000))
            if not info:
                return
            addresses = info.parsed_addresses()
            for ip in addresses:
                if ":" in ip:
                    continue
                entry = out.setdefault(ip, {"host": "", "services": []})
                host = (info.server or "").rstrip(".")
                if host:
                    entry["host"] = host
                services = entry["services"]
                if isinstance(services, list):
                    short = service_type.replace(".local.", "")
                    label = f"{short}:{name}"
                    if label not in services:
                        services.append(label)

        def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            self.add_service(zc, service_type, name)

        def remove_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            return

    zc = Zeroconf()
    listener = Listener()
    browsers = [ServiceBrowser(zc, st, listener) for st in service_types]
    time.sleep(timeout_s)
    for browser in browsers:
        browser.cancel()
    zc.close()
    return out


def http_banner_probe(ip: str, port: int, timeout_s: float = 1.5) -> str | None:
    req = b"GET / HTTP/1.0\r\nHost: local\r\n\r\n"
    try:
        if port == 443 or port == 8443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout_s) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                    ssock.sendall(req)
                    resp = ssock.recv(2048).decode(errors="ignore")
        else:
            with socket.create_connection((ip, port), timeout=timeout_s) as sock:
                sock.sendall(req)
                resp = sock.recv(2048).decode(errors="ignore")

        m = re.search(r"^Server:\s*(.+)$", resp, flags=re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()
    except Exception:
        return None
    return None


def smb_status(ip: str, timeout_s: int = 3) -> list[str]:
    if not shutil.which("smbutil"):
        return []

    try:
        proc = subprocess.run(
            ["smbutil", "status", ip],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except Exception:
        return []

    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "NetBIOS" in line or "Workgroup" in line or "Name" in line:
            out.append(line)
    return out[:5]


def nmap_scan(ip: str, timeout_s: int = 70) -> tuple[str | None, list[int], list[str], list[str]]:
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        for fallback in ("/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap"):
            if os.path.exists(fallback):
                nmap_bin = fallback
                break

    if not nmap_bin:
        return None, [], [], ["nmap not installed"]

    host_timeout = os.environ.get("NMAP_HOST_TIMEOUT", "45s")
    max_retries = os.environ.get("NMAP_MAX_RETRIES", "1")
    timing = os.environ.get("NMAP_TIMING", "4")

    os_cmd = [
        nmap_bin,
        "-Pn",
        "-O",
        "--osscan-limit",
        "--max-retries",
        max_retries,
        "-T",
        timing,
        "--host-timeout",
        host_timeout,
        "-oX",
        "-",
        ip,
    ]
    port_cmd = [
        nmap_bin,
        "-Pn",
        "--top-ports",
        "200",
        "--open",
        "--max-retries",
        max_retries,
        "-T",
        timing,
        "--host-timeout",
        host_timeout,
        "-oX",
        "-",
        ip,
    ]

    os_guess = None
    open_ports: list[int] = []
    services: list[str] = []
    evidence: list[str] = []

    try:
        proc_os = subprocess.run(os_cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
        if proc_os.stdout.strip():
            root_os = ET.fromstring(proc_os.stdout)
            host_os = root_os.find("host")
            if host_os is not None:
                os_match = host_os.find("./os/osmatch")
                if os_match is not None:
                    os_name = os_match.attrib.get("name")
                    acc = os_match.attrib.get("accuracy")
                    if os_name:
                        os_guess = os_name
                        evidence.append(f"nmap osmatch: {os_name} ({acc or '?'}%)")
        else:
            stderr = (proc_os.stderr or "").strip()
            if stderr:
                evidence.append(f"nmap os scan: {stderr.splitlines()[0][:120]}")
    except subprocess.TimeoutExpired:
        evidence.append("nmap os scan timeout")
    except Exception as exc:
        evidence.append(f"nmap os scan error: {exc}")

    try:
        proc_ports = subprocess.run(port_cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
        if proc_ports.stdout.strip():
            root_ports = ET.fromstring(proc_ports.stdout)
            host_ports = root_ports.find("host")
            if host_ports is not None:
                for port in host_ports.findall("./ports/port"):
                    state = port.find("./state")
                    if state is None or state.attrib.get("state") != "open":
                        continue
                    try:
                        port_id = int(port.attrib.get("portid", "0"))
                    except ValueError:
                        continue
                    if port_id:
                        open_ports.append(port_id)
                        services.append(f"{port_id}/open")
        else:
            stderr = (proc_ports.stderr or "").strip()
            if stderr:
                evidence.append(f"nmap port scan: {stderr.splitlines()[0][:120]}")
    except subprocess.TimeoutExpired:
        evidence.append("nmap port scan timeout")
    except Exception as exc:
        evidence.append(f"nmap port scan error: {exc}")

    return os_guess, sorted(set(open_ports)), sorted(set(services)), evidence


def infer_os(vendor: str | None, services: list[str], ssdp: dict[str, str], smb_lines: list[str]) -> str | None:
    joined = " ".join(services + smb_lines + list(ssdp.values())).lower()

    if "microsoft" in joined or "windows" in joined:
        return "Windows"
    if "apple" in (vendor or "").lower() or "airplay" in joined or "darwin" in joined:
        return "Apple family (macOS/iOS/tvOS)"
    if "android" in joined:
        return "Android"
    if "linux" in joined or "openssh" in joined:
        return "Linux/Unix"
    return None


def infer_device_type(mac: str, os_guess: str | None, services: list[str], open_ports: list[int]) -> str:
    joined = " ".join(services).lower()
    os_text = (os_guess or "").lower()

    if is_locally_administered_mac(mac):
        return "Mobile"
    if "ios" in os_text or "android" in os_text:
        return "Mobile"
    if any(token in joined for token in ("airplay", "raop", "googlecast", "companion", "android")):
        return "Mobile"

    wired_ports = {22, 53, 139, 445, 515, 631, 9100, 1723, 3389}
    if wired_ports.intersection(set(open_ports)):
        return "Wired"
    if "windows" in os_text or "linux" in os_text:
        return "Wired"
    return "Unknown"


def score_confidence(os_guess: str | None, evidence: list[str], open_ports: list[int]) -> float:
    score = 0.15
    if os_guess:
        score += 0.35
    if open_ports:
        score += min(0.25, 0.03 * len(open_ports))
    if evidence:
        score += min(0.25, 0.04 * len(evidence))
    return round(min(score, 0.95), 2)


def enrich_device(
    ip: str,
    mac: str,
    hostname: str | None,
    ssdp_cache: dict[str, dict[str, str]],
    mdns_cache: dict[str, dict[str, list[str] | str]],
) -> EnrichmentResult:
    vendor = lookup_vendor(mac)
    evidence: list[str] = []
    services: list[str] = []
    open_ports: list[int] = []
    resolved_hostname = hostname
    sources: set[str] = set()

    if vendor:
        evidence.append(f"mac vendor hint: {vendor}")
        sources.add("oui")

    ssdp_data = ssdp_cache.get(ip, {})
    if ssdp_data:
        server = ssdp_data.get("server", "")
        st = ssdp_data.get("st", "")
        if server:
            services.append(f"ssdp server: {server}")
        if st:
            services.append(f"ssdp st: {st}")
        evidence.append("ssdp response present")
        sources.add("ssdp")

    mdns_data = mdns_cache.get(ip, {})
    if mdns_data:
        mdns_host = str(mdns_data.get("host", "")).strip()
        if mdns_host:
            resolved_hostname = resolved_hostname or mdns_host
            services.append(f"mdns host: {mdns_host}")
        mdns_services = mdns_data.get("services", [])
        if isinstance(mdns_services, list):
            for svc in mdns_services[:8]:
                services.append(f"mdns: {svc}")
        evidence.append("mdns/bonjour service observed")
        sources.add("mdns")

    for port in (80, 443, 8080, 8443):
        banner = http_banner_probe(ip, port)
        if banner:
            services.append(f"http[{port}] server: {banner}")
            open_ports.append(port)
            evidence.append(f"http banner on {port}")
            sources.add("http")

    smb_lines = smb_status(ip)
    if smb_lines:
        services.extend(f"smb: {line}" for line in smb_lines)
        evidence.append("smb status available")
        sources.add("smb")

    nmap_os, nmap_ports, nmap_services, nmap_evidence = nmap_scan(ip)
    if nmap_ports:
        open_ports.extend(nmap_ports)
    if nmap_services:
        services.extend(nmap_services)
    evidence.extend(nmap_evidence)
    if nmap_os or nmap_ports or nmap_services or nmap_evidence:
        sources.add("nmap")

    os_guess = nmap_os or infer_os(vendor, services, ssdp_data, smb_lines)
    if hostname and hostname.endswith(".local"):
        evidence.append("bonjour-style hostname (.local)")
    device_type = infer_device_type(mac, os_guess, services, open_ports)

    open_ports = sorted(set(open_ports))
    services = sorted(set(services))
    confidence = score_confidence(os_guess, evidence, open_ports)

    return EnrichmentResult(
        hostname=resolved_hostname,
        vendor=vendor,
        device_type=device_type,
        os_guess=os_guess,
        confidence=confidence,
        open_ports=open_ports,
        services=services,
        evidence=evidence[:12],
        sources=sorted(sources),
    )
