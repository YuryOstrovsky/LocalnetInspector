from __future__ import annotations

import json
import threading
import time
import os
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
import PySide6

from localnet_inspector.core.enrichment import enrich_device, mdns_discover, ssdp_discover
from localnet_inspector.core.dhcp_sniffer import listen_dhcp
from localnet_inspector.core.network import active_arp_scan, detect_primary_network
from localnet_inspector.core.storage import DeviceStore


class MainWindow(QMainWindow):
    def __init__(self, store: DeviceStore, subnet: str, iface: str | None) -> None:
        super().__init__()
        self.store = store
        self.subnet = subnet
        self.iface = iface
        self.running = False

        self.setWindowTitle("Localnet Inspector")
        self.resize(1100, 600)

        container = QWidget()
        layout = QVBoxLayout(container)

        header = QHBoxLayout()
        iface_label = self.iface or "auto"
        self.status = QLabel(f"Subnet: {self.subnet} | Iface: {iface_label} | Stopped")
        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.scan_btn = QPushButton("Scan Now")
        self.enrich_btn = QPushButton("Enrich Now")

        self.start_btn.clicked.connect(self.start_collectors)
        self.stop_btn.clicked.connect(self.stop_collectors)
        self.scan_btn.clicked.connect(self.scan_once)
        self.enrich_btn.clicked.connect(self.enrich_now)

        header.addWidget(self.status)
        header.addWidget(self.start_btn)
        header.addWidget(self.stop_btn)
        header.addWidget(self.scan_btn)
        header.addWidget(self.enrich_btn)

        self.table = QTableWidget()
        self.table.setColumnCount(12)
        self.table.setHorizontalHeaderLabels(
            [
                "IP",
                "MAC",
                "Hostname",
                "Vendor",
                "Device Type",
                "OS Guess",
                "Confidence",
                "Open Ports",
                "mDNS/Bonjour",
                "Source",
                "First Seen",
                "Last Seen",
            ]
        )
        self.table.horizontalHeader().setStretchLastSection(True)

        layout.addLayout(header)
        layout.addWidget(self.table)

        self.setCentralWidget(container)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_table)
        self.refresh_timer.start(2000)

        self.scan_thread: threading.Thread | None = None
        self.dhcp_thread: threading.Thread | None = None
        self.enrich_thread: threading.Thread | None = None

    def start_collectors(self) -> None:
        if self.running:
            return
        self.running = True
        iface_label = self.iface or "auto"
        self.status.setText(f"Subnet: {self.subnet} | Iface: {iface_label} | Running")

        # Trigger immediate discovery before background loops.
        self.scan_once()

        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()

        self.dhcp_thread = threading.Thread(target=self._dhcp_loop, daemon=True)
        self.dhcp_thread.start()

    def stop_collectors(self) -> None:
        self.running = False
        iface_label = self.iface or "auto"
        self.status.setText(f"Subnet: {self.subnet} | Iface: {iface_label} | Stopped")

    def scan_once(self) -> None:
        try:
            devices = active_arp_scan(self.subnet, iface=self.iface)
            self.store.bulk_upsert(devices)
            iface_label = self.iface or "auto"
            self.status.setText(
                f"Subnet: {self.subnet} | Iface: {iface_label} | Scan completed ({len(devices)} devices)"
            )
        except Exception as exc:
            self.status.setText(f"Scan failed: {exc}")

    def _scan_loop(self) -> None:
        while self.running:
            try:
                devices = active_arp_scan(self.subnet, iface=self.iface)
                self.store.bulk_upsert(devices)
                iface_label = self.iface or "auto"
                self.status.setText(
                    f"Subnet: {self.subnet} | Iface: {iface_label} | Background scan ({len(devices)} devices)"
                )
            except Exception as exc:
                self.status.setText(f"Background scan failed: {exc}")
            time.sleep(60)

    def _dhcp_loop(self) -> None:
        def _ingest(device):
            self.store.upsert_device(device)

        try:
            listen_dhcp(_ingest, iface=self.iface)
        except Exception as exc:
            # On macOS this can fail without sudo / packet capture permissions.
            self.status.setText(f"DHCP listener failed: {exc}")

    def enrich_now(self) -> None:
        if self.enrich_thread and self.enrich_thread.is_alive():
            self.status.setText("Enrichment already running...")
            return

        self.enrich_thread = threading.Thread(target=self._enrich_loop, daemon=True)
        self.enrich_thread.start()

    def _enrich_loop(self) -> None:
        rows = self.store.get_all_devices()
        candidates = [row for row in rows if row["ip"] and row["ip"] != "0.0.0.0"]
        if not candidates:
            self.status.setText("No devices to enrich yet.")
            return

        self.status.setText(f"Enrichment started ({len(candidates)} devices)...")
        ssdp_cache = ssdp_discover()
        mdns_cache = mdns_discover()

        completed = 0
        for row in candidates:
            result = enrich_device(
                ip=row["ip"],
                mac=row["mac"],
                hostname=row["hostname"],
                ssdp_cache=ssdp_cache,
                mdns_cache=mdns_cache,
            )
            self.store.upsert_enrichment(
                mac=row["mac"],
                vendor=result.vendor,
                hostname=result.hostname,
                device_type=result.device_type,
                os_guess=result.os_guess,
                confidence=result.confidence,
                open_ports=result.open_ports,
                services=result.services,
                evidence=result.evidence,
                sources=result.sources,
            )
            completed += 1
            self.status.setText(f"Enrichment running... {completed}/{len(candidates)}")

        self.status.setText(f"Enrichment completed ({completed} devices)")

    def refresh_table(self) -> None:
        rows = self.store.get_all_devices()
        self.table.setRowCount(len(rows))

        for i, row in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(row["ip"] or ""))
            self.table.setItem(i, 1, QTableWidgetItem(row["mac"] or ""))
            self.table.setItem(i, 2, QTableWidgetItem(row["hostname"] or ""))
            self.table.setItem(i, 3, QTableWidgetItem(row["vendor"] or ""))
            self.table.setItem(i, 4, QTableWidgetItem(row["device_type"] or "Unknown"))
            self.table.setItem(i, 5, QTableWidgetItem(row["os_guess"] or ""))
            confidence = "" if row["confidence"] is None else f"{float(row['confidence']):.2f}"
            self.table.setItem(i, 6, QTableWidgetItem(confidence))

            ports_text = ""
            if row["open_ports"]:
                try:
                    ports_text = ",".join(str(v) for v in json.loads(row["open_ports"]))
                except Exception:
                    ports_text = row["open_ports"] or ""
            self.table.setItem(i, 7, QTableWidgetItem(ports_text))

            mdns_text = ""
            if row["services"]:
                try:
                    services = [str(s) for s in json.loads(row["services"])]
                    mdns_hits = [s for s in services if s.startswith("mdns")]
                    mdns_text = "; ".join(mdns_hits[:2])
                except Exception:
                    mdns_text = ""
            self.table.setItem(i, 8, QTableWidgetItem(mdns_text))
            self.table.setItem(i, 9, QTableWidgetItem(row["source"] or ""))
            self.table.setItem(i, 10, QTableWidgetItem(row["first_seen"] or ""))
            self.table.setItem(i, 11, QTableWidgetItem(row["last_seen"] or ""))


def run() -> None:
    # Explicitly set Qt plugin paths. This avoids macOS path parsing issues
    # (for example OneDrive paths with commas) where Qt cannot find "cocoa".
    pyside_dir = Path(PySide6.__file__).resolve().parent
    qt_plugins = pyside_dir / "Qt" / "plugins"
    qt_platform_plugins = qt_plugins / "platforms"
    if qt_plugins.exists():
        os.environ.setdefault("QT_PLUGIN_PATH", str(qt_plugins))
    if qt_platform_plugins.exists():
        os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", str(qt_platform_plugins))

    app = QApplication([])
    project_root = Path(__file__).resolve().parents[3]
    db_path = project_root / "data" / "devices.db"
    store = DeviceStore(db_path)
    subnet, iface = detect_primary_network()
    iface = os.environ.get("LOCALNET_IFACE", iface)
    window = MainWindow(store, subnet, iface)
    window.show()
    app.exec()
