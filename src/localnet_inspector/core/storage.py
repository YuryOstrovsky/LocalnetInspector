from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import DeviceRecord


class DeviceStore:
    SOURCE_ORDER = ["arp", "dhcp", "oui", "mdns", "ssdp", "http", "smb", "nmap"]

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    source TEXT NOT NULL,
                    dhcp_fingerprint TEXT,
                    os_guess TEXT,
                    confidence REAL,
                    open_ports TEXT,
                    services TEXT,
                    evidence TEXT,
                    last_enriched TEXT
                )
                """
            )
            self._ensure_column(conn, "confidence", "REAL")
            self._ensure_column(conn, "open_ports", "TEXT")
            self._ensure_column(conn, "services", "TEXT")
            self._ensure_column(conn, "evidence", "TEXT")
            self._ensure_column(conn, "last_enriched", "TEXT")
            self._ensure_column(conn, "device_type", "TEXT")

    def _ensure_column(self, conn: sqlite3.Connection, column: str, column_type: str) -> None:
        columns = conn.execute("PRAGMA table_info(devices)").fetchall()
        names = {row[1] for row in columns}
        if column not in names:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {column_type}")

    @classmethod
    def _normalize_sources(cls, source_value: str | None) -> list[str]:
        if not source_value:
            return []
        tokens = [token.strip().lower() for token in source_value.split("/") if token.strip()]
        unique = sorted(set(tokens), key=lambda t: cls.SOURCE_ORDER.index(t) if t in cls.SOURCE_ORDER else 999)
        return unique

    @classmethod
    def _merge_source_values(cls, *source_values: str | None, extra: list[str] | None = None) -> str:
        all_tokens: list[str] = []
        for value in source_values:
            all_tokens.extend(cls._normalize_sources(value))
        if extra:
            all_tokens.extend(token.strip().lower() for token in extra if token and token.strip())
        unique = sorted(set(all_tokens), key=lambda t: cls.SOURCE_ORDER.index(t) if t in cls.SOURCE_ORDER else 999)
        return "/".join(unique)

    def upsert_device(self, device: DeviceRecord) -> None:
        now = datetime.utcnow().isoformat(timespec="seconds")
        ip_value = device.ip if device.ip and device.ip != "0.0.0.0" else None
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT mac, first_seen, source FROM devices WHERE mac = ?", (device.mac,)
            ).fetchone()

            if existing:
                merged_source = self._merge_source_values(existing["source"], device.source)
                conn.execute(
                    """
                    UPDATE devices
                    SET ip = COALESCE(?, ip), hostname = COALESCE(?, hostname), vendor = COALESCE(?, vendor),
                        last_seen = ?, source = ?,
                        dhcp_fingerprint = COALESCE(?, dhcp_fingerprint),
                        os_guess = COALESCE(?, os_guess)
                    WHERE mac = ?
                    """,
                    (
                        ip_value,
                        device.hostname,
                        device.vendor,
                        now,
                        merged_source,
                        device.dhcp_fingerprint,
                        device.os_guess,
                        device.mac,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO devices
                    (mac, ip, hostname, vendor, first_seen, last_seen, source, dhcp_fingerprint, os_guess,
                     confidence, open_ports, services, evidence, last_enriched, device_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL)
                    """,
                    (
                        device.mac,
                        ip_value or device.ip,
                        device.hostname,
                        device.vendor,
                        now,
                        now,
                        self._merge_source_values(device.source),
                        device.dhcp_fingerprint,
                        device.os_guess,
                    ),
                )

    def upsert_enrichment(
        self,
        mac: str,
        vendor: str | None,
        hostname: str | None,
        device_type: str | None,
        os_guess: str | None,
        confidence: float | None,
        open_ports: list[int],
        services: list[str],
        evidence: list[str],
        sources: list[str],
    ) -> None:
        now = datetime.utcnow().isoformat(timespec="seconds")
        with self._connect() as conn:
            existing = conn.execute("SELECT source FROM devices WHERE mac = ?", (mac,)).fetchone()
            merged_source = self._merge_source_values(existing["source"] if existing else None, extra=sources)
            conn.execute(
                """
                UPDATE devices
                SET vendor = COALESCE(?, vendor),
                    hostname = COALESCE(?, hostname),
                    device_type = COALESCE(?, device_type),
                    source = ?,
                    os_guess = COALESCE(?, os_guess),
                    confidence = COALESCE(?, confidence),
                    open_ports = ?,
                    services = ?,
                    evidence = ?,
                    last_enriched = ?
                WHERE mac = ?
                """,
                (
                    vendor,
                    hostname,
                    device_type,
                    merged_source,
                    os_guess,
                    confidence,
                    json.dumps(open_ports),
                    json.dumps(services),
                    json.dumps(evidence),
                    now,
                    mac,
                ),
            )

    def get_all_devices(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT mac, ip, hostname, vendor, first_seen, last_seen, source,
                       dhcp_fingerprint, os_guess, device_type, confidence, open_ports, services,
                       evidence, last_enriched
                FROM devices
                ORDER BY datetime(last_seen) DESC
                """
            ).fetchall()
        return list(rows)

    def bulk_upsert(self, devices: Iterable[DeviceRecord]) -> None:
        for device in devices:
            self.upsert_device(device)
