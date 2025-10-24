"""Database models and manager for USB Threat Detection."""

import sqlite3
import logging
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from contextlib import contextmanager


logger = logging.getLogger(__name__)


class USBEvent:
    """Represents a USB device event."""

    def __init__(
        self,
        event_id: Optional[int] = None,
        timestamp: Optional[datetime] = None,
        event_type: str = "",
        vendor_id: str = "",
        product_id: str = "",
        serial_number: str = "",
        device_name: str = "",
        manufacturer: str = "",
        is_threat: bool = False,
        threat_score: int = 0,
        threat_details: str = "",
        device_class: str = "",
        mount_point: str = "",
    ):
        self.event_id = event_id
        self.timestamp = timestamp or datetime.now()
        self.event_type = event_type  # 'connected', 'disconnected'
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.serial_number = serial_number
        self.device_name = device_name
        self.manufacturer = manufacturer
        self.is_threat = is_threat
        self.threat_score = threat_score
        self.threat_details = threat_details
        self.device_class = device_class
        self.mount_point = mount_point

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "device_name": self.device_name,
            "manufacturer": self.manufacturer,
            "is_threat": self.is_threat,
            "threat_score": self.threat_score,
            "threat_details": self.threat_details,
            "device_class": self.device_class,
            "mount_point": self.mount_point,
        }

    @classmethod
    def from_row(cls, row: Tuple) -> "USBEvent":
        """Create USBEvent from database row."""
        return cls(
            event_id=row[0],
            timestamp=datetime.fromisoformat(row[1]) if row[1] else None,
            event_type=row[2],
            vendor_id=row[3],
            product_id=row[4],
            serial_number=row[5],
            device_name=row[6],
            manufacturer=row[7],
            is_threat=bool(row[8]),
            threat_score=row[9],
            threat_details=row[10],
            device_class=row[11],
            mount_point=row[12],
        )


class ThreatSignature:
    """Represents a threat signature from intelligence feeds."""

    def __init__(
        self,
        signature_id: Optional[int] = None,
        signature_type: str = "",
        indicator: str = "",
        description: str = "",
        severity: str = "medium",
        source: str = "",
        created_at: Optional[datetime] = None,
        last_updated: Optional[datetime] = None,
        metadata: str = "",
    ):
        self.signature_id = signature_id
        self.signature_type = signature_type  # 'vid_pid', 'file_hash', 'filename', etc.
        self.indicator = indicator
        self.description = description
        self.severity = severity  # 'low', 'medium', 'high', 'critical'
        self.source = source
        self.created_at = created_at or datetime.now()
        self.last_updated = last_updated or datetime.now()
        self.metadata = metadata

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "signature_id": self.signature_id,
            "signature_type": self.signature_type,
            "indicator": self.indicator,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_row(cls, row: Tuple) -> "ThreatSignature":
        """Create ThreatSignature from database row."""
        return cls(
            signature_id=row[0],
            signature_type=row[1],
            indicator=row[2],
            description=row[3],
            severity=row[4],
            source=row[5],
            created_at=datetime.fromisoformat(row[6]) if row[6] else None,
            last_updated=datetime.fromisoformat(row[7]) if row[7] else None,
            metadata=row[8],
        )


class WhitelistEntry:
    """Represents a whitelisted USB device."""

    def __init__(
        self,
        entry_id: Optional[int] = None,
        vendor_id: str = "",
        product_id: str = "",
        serial_number: str = "",
        description: str = "",
        added_at: Optional[datetime] = None,
    ):
        self.entry_id = entry_id
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.serial_number = serial_number
        self.description = description
        self.added_at = added_at or datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "entry_id": self.entry_id,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "description": self.description,
            "added_at": self.added_at.isoformat() if self.added_at else None,
        }

    @classmethod
    def from_row(cls, row: Tuple) -> "WhitelistEntry":
        """Create WhitelistEntry from database row."""
        return cls(
            entry_id=row[0],
            vendor_id=row[1],
            product_id=row[2],
            serial_number=row[3],
            description=row[4],
            added_at=datetime.fromisoformat(row[5]) if row[5] else None,
        )


class DatabaseManager:
    """Manages database operations for USB Threat Detection."""

    def __init__(self, db_path: str = "usb_threat_detection.db", wal_mode: bool = True):
        """Initialize database manager.

        Args:
            db_path: Path to SQLite database file
            wal_mode: Enable Write-Ahead Logging for better concurrency
        """
        self.db_path = db_path
        self.wal_mode = wal_mode
        self._init_database()

    def _init_database(self):
        """Initialize database schema."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Enable WAL mode if requested
                if self.wal_mode:
                    cursor.execute("PRAGMA journal_mode=WAL")

                # Create USB events table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS usb_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        vendor_id TEXT,
                        product_id TEXT,
                        serial_number TEXT,
                        device_name TEXT,
                        manufacturer TEXT,
                        is_threat INTEGER DEFAULT 0,
                        threat_score INTEGER DEFAULT 0,
                        threat_details TEXT,
                        device_class TEXT,
                        mount_point TEXT
                    )
                """)

                # Create threat signatures table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_signatures (
                        signature_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_type TEXT NOT NULL,
                        indicator TEXT NOT NULL,
                        description TEXT,
                        severity TEXT DEFAULT 'medium',
                        source TEXT,
                        created_at TEXT NOT NULL,
                        last_updated TEXT NOT NULL,
                        metadata TEXT,
                        UNIQUE(signature_type, indicator)
                    )
                """)

                # Create whitelist table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS whitelist (
                        entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        vendor_id TEXT NOT NULL,
                        product_id TEXT NOT NULL,
                        serial_number TEXT,
                        description TEXT,
                        added_at TEXT NOT NULL,
                        UNIQUE(vendor_id, product_id, serial_number)
                    )
                """)

                # Create indexes for better performance
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_events_timestamp
                    ON usb_events(timestamp)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_events_threat
                    ON usb_events(is_threat)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_signatures_type
                    ON threat_signatures(signature_type)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_whitelist_device
                    ON whitelist(vendor_id, product_id)
                """)

                conn.commit()
                logger.info("Database initialized successfully")

        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise

    @contextmanager
    def _get_connection(self):
        """Get database connection context manager."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            yield conn
        finally:
            conn.close()

    def add_event(self, event: USBEvent) -> int:
        """Add USB event to database.

        Args:
            event: USBEvent object to add

        Returns:
            ID of inserted event
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO usb_events
                    (timestamp, event_type, vendor_id, product_id, serial_number,
                     device_name, manufacturer, is_threat, threat_score,
                     threat_details, device_class, mount_point)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.vendor_id,
                    event.product_id,
                    event.serial_number,
                    event.device_name,
                    event.manufacturer,
                    int(event.is_threat),
                    event.threat_score,
                    event.threat_details,
                    event.device_class,
                    event.mount_point,
                ))
                conn.commit()
                return cursor.lastrowid

        except sqlite3.Error as e:
            logger.error(f"Error adding event: {e}")
            raise

    def get_recent_events(self, limit: int = 100) -> List[USBEvent]:
        """Get recent USB events.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of USBEvent objects
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM usb_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                return [USBEvent.from_row(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error(f"Error getting events: {e}")
            return []

    def get_threat_events(self, limit: int = 100) -> List[USBEvent]:
        """Get threat events only.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of threat USBEvent objects
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM usb_events
                    WHERE is_threat = 1
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                return [USBEvent.from_row(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error(f"Error getting threat events: {e}")
            return []

    def add_signature(self, signature: ThreatSignature) -> int:
        """Add or update threat signature.

        Args:
            signature: ThreatSignature object to add

        Returns:
            ID of inserted/updated signature
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO threat_signatures
                    (signature_type, indicator, description, severity, source,
                     created_at, last_updated, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    signature.signature_type,
                    signature.indicator,
                    signature.description,
                    signature.severity,
                    signature.source,
                    signature.created_at.isoformat(),
                    signature.last_updated.isoformat(),
                    signature.metadata,
                ))
                conn.commit()
                return cursor.lastrowid

        except sqlite3.Error as e:
            logger.error(f"Error adding signature: {e}")
            raise

    def get_signatures(self, signature_type: Optional[str] = None) -> List[ThreatSignature]:
        """Get threat signatures.

        Args:
            signature_type: Filter by signature type (optional)

        Returns:
            List of ThreatSignature objects
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if signature_type:
                    cursor.execute("""
                        SELECT * FROM threat_signatures
                        WHERE signature_type = ?
                        ORDER BY last_updated DESC
                    """, (signature_type,))
                else:
                    cursor.execute("""
                        SELECT * FROM threat_signatures
                        ORDER BY last_updated DESC
                    """)
                return [ThreatSignature.from_row(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error(f"Error getting signatures: {e}")
            return []

    def add_whitelist_entry(self, entry: WhitelistEntry) -> int:
        """Add device to whitelist.

        Args:
            entry: WhitelistEntry object to add

        Returns:
            ID of inserted entry
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO whitelist
                    (vendor_id, product_id, serial_number, description, added_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    entry.vendor_id,
                    entry.product_id,
                    entry.serial_number,
                    entry.description,
                    entry.added_at.isoformat(),
                ))
                conn.commit()
                return cursor.lastrowid

        except sqlite3.Error as e:
            logger.error(f"Error adding whitelist entry: {e}")
            raise

    def is_whitelisted(self, vendor_id: str, product_id: str, serial_number: str = "") -> bool:
        """Check if device is whitelisted.

        Args:
            vendor_id: Vendor ID
            product_id: Product ID
            serial_number: Serial number (optional)

        Returns:
            True if device is whitelisted
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if serial_number:
                    cursor.execute("""
                        SELECT COUNT(*) FROM whitelist
                        WHERE vendor_id = ? AND product_id = ? AND serial_number = ?
                    """, (vendor_id, product_id, serial_number))
                else:
                    cursor.execute("""
                        SELECT COUNT(*) FROM whitelist
                        WHERE vendor_id = ? AND product_id = ?
                    """, (vendor_id, product_id))
                return cursor.fetchone()[0] > 0

        except sqlite3.Error as e:
            logger.error(f"Error checking whitelist: {e}")
            return False

    def get_whitelist(self) -> List[WhitelistEntry]:
        """Get all whitelist entries.

        Returns:
            List of WhitelistEntry objects
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM whitelist ORDER BY added_at DESC")
                return [WhitelistEntry.from_row(row) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error(f"Error getting whitelist: {e}")
            return []

    def remove_whitelist_entry(self, entry_id: int) -> bool:
        """Remove device from whitelist.

        Args:
            entry_id: ID of whitelist entry to remove

        Returns:
            True if successful
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM whitelist WHERE entry_id = ?", (entry_id,))
                conn.commit()
                return cursor.rowcount > 0

        except sqlite3.Error as e:
            logger.error(f"Error removing whitelist entry: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics.

        Returns:
            Dictionary with statistics
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM usb_events")
                total_events = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM usb_events WHERE is_threat = 1")
                threat_events = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM threat_signatures")
                total_signatures = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM whitelist")
                whitelist_count = cursor.fetchone()[0]

                return {
                    "total_events": total_events,
                    "threat_events": threat_events,
                    "total_signatures": total_signatures,
                    "whitelist_count": whitelist_count,
                }

        except sqlite3.Error as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
