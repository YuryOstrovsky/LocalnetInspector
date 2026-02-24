# Localnet Inspector (macOS)

A local macOS desktop app (Python + PySide6) that:
- Actively discovers devices on your subnet (ARP scan)
- Runs multi-signal enrichment (nmap + SSDP + mDNS/Bonjour + SMB + HTTP/TLS hints)
- Classifies likely `Device Type` (`Mobile`, `Wired`, `Unknown`)
- Stores device history in local SQLite (`data/devices.db`)

## 1) Prerequisites

- macOS (Apple Silicon or Intel)
- Python 3.11+
- Homebrew (recommended)

Install base tools:

```bash
brew install python@3.11
```

Optional for `.dmg` packaging:

```bash
brew install create-dmg
```

Optional but recommended for active OS fingerprinting:

```bash
brew install nmap
```

## 2) Setup

```bash
cd /Users/yostrovs/Documents/New\ project/localnet-inspector
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
pip install -e .
```

## 3) Run the app

Packet capture and ARP scanning often require elevated privileges.

```bash
cd /Users/yostrovs/Documents/New\ project/localnet-inspector
./scripts/run_with_sudo.sh
```

UI behavior:
- `Start`: starts periodic ARP scan loop (every 60s) + DHCP listener
- `Scan Now`: single immediate ARP scan
- `Enrich Now`: runs OUI + SSDP + mDNS/Bonjour + HTTP/TLS + SMB probes and optional `nmap` OS scan
- Table auto-refreshes every 2s
- `Source` column is cumulative per device (example: `arp/nmap/mdns/http`)

If you want to start only the UI without elevated capture privileges:

```bash
cd /Users/yostrovs/Documents/New\ project/localnet-inspector
source .venv/bin/activate
python -m localnet_inspector
```

## 4) How enrichment works

- App builds confidence from multiple signals and stores evidence.
- `nmap` contributes strongest OS and open-port hints.
- mDNS/Bonjour and SSDP help identify Apple/IoT/service-capable endpoints.
- Devices are categorized into `Mobile`/`Wired`/`Unknown` from combined traits.

## 5) Build local `.app` executable

```bash
cd /Users/yostrovs/Documents/New\ project/localnet-inspector
source .venv/bin/activate
./scripts/build_app.sh
```

Output:
- `dist/LocalnetInspector.app`

## 6) Build `.dmg`

```bash
cd /Users/yostrovs/Documents/New\ project/localnet-inspector
./scripts/build_dmg.sh
```

Output:
- `dist/LocalnetInspector.dmg`

## 7) Keep it running continuously (recommended path)

For constant collection in your subnet, run as a LaunchAgent/LaunchDaemon.

- Use a `launchd` plist to auto-start on login or boot.
- If you need continuous sniffing without manual sudo prompt, configure permissions carefully (or run as root-managed service).

## 8) Important limitations

- DHCP passive collection only sees renewals/new negotiations while app is running.
- On switched networks, you only capture broadcast DHCP traffic visible to your host.
- Many modern mobile clients expose minimal probeable services, so confidence can stay low.
- Device type classification is probabilistic, not guaranteed exact.

## 9) Next improvements

- Expand OUI mappings using full IEEE database import.
- Improve mDNS per-device mapping (service instance to IP resolution).
- Add export/report views (CSV/JSON with evidence trail).
- Add policy-driven scan profiles (fast, balanced, deep).
