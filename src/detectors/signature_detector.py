"""Signature-based threat detection."""

import logging
from typing import List, Dict, Any, Tuple
from src.monitors.base_monitor import USBDevice
from src.database.models import ThreatSignature, DatabaseManager

logger = logging.getLogger(__name__)


class SignatureDetector:
    """Signature-based USB threat detector."""

    def __init__(self, db_manager: DatabaseManager):
        """Initialize signature detector.

        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self._signatures_cache: Dict[str, List[ThreatSignature]] = {}
        self._load_builtin_signatures()
        self._load_signatures_from_db()

    def _load_builtin_signatures(self):
        """Load built-in threat signatures."""
        builtin_signatures = [
            # Known malicious USB devices
            ThreatSignature(
                signature_type="vid_pid",
                indicator="0x1234:0x5678",
                description="Known malicious USB device (example)",
                severity="high",
                source="builtin",
            ),
            # Suspicious device classes
            ThreatSignature(
                signature_type="device_class",
                indicator="0x08",  # Mass storage
                description="Mass storage device (potential risk)",
                severity="low",
                source="builtin",
            ),
            ThreatSignature(
                signature_type="device_class",
                indicator="0x03",  # HID
                description="HID device (keyboard emulation risk)",
                severity="medium",
                source="builtin",
            ),
            # Known BadUSB vendor IDs
            ThreatSignature(
                signature_type="vendor_id",
                indicator="0x16c0",  # VOTI - often used in DIY BadUSB
                description="Vendor ID commonly used in BadUSB devices",
                severity="medium",
                source="builtin",
            ),
        ]

        # Add built-in signatures to database if not exists
        for sig in builtin_signatures:
            try:
                self.db_manager.add_signature(sig)
            except Exception as e:
                logger.debug(f"Signature already exists or error: {e}")

    def _load_signatures_from_db(self):
        """Load signatures from database into cache."""
        try:
            signatures = self.db_manager.get_signatures()
            self._signatures_cache.clear()

            for sig in signatures:
                if sig.signature_type not in self._signatures_cache:
                    self._signatures_cache[sig.signature_type] = []
                self._signatures_cache[sig.signature_type].append(sig)

            logger.info(f"Loaded {len(signatures)} signatures from database")

        except Exception as e:
            logger.error(f"Error loading signatures: {e}")

    def reload_signatures(self):
        """Reload signatures from database."""
        self._load_signatures_from_db()

    def check_device(self, device: USBDevice) -> Tuple[bool, int, List[str]]:
        """Check device against signature database.

        Args:
            device: USB device to check

        Returns:
            Tuple of (is_threat, threat_score, matched_signatures)
        """
        matched = []
        threat_score = 0
        severity_scores = {"low": 20, "medium": 50, "high": 80, "critical": 100}

        # Check VID:PID combination
        vid_pid = device.get_vid_pid()
        if "vid_pid" in self._signatures_cache:
            for sig in self._signatures_cache["vid_pid"]:
                if sig.indicator.lower() == vid_pid.lower():
                    matched.append(f"VID:PID match: {sig.description}")
                    threat_score = max(threat_score, severity_scores.get(sig.severity, 50))

        # Check vendor ID alone
        if "vendor_id" in self._signatures_cache and device.vendor_id:
            for sig in self._signatures_cache["vendor_id"]:
                if sig.indicator.lower() == device.vendor_id.lower():
                    matched.append(f"Vendor ID match: {sig.description}")
                    threat_score = max(threat_score, severity_scores.get(sig.severity, 50))

        # Check product ID alone
        if "product_id" in self._signatures_cache and device.product_id:
            for sig in self._signatures_cache["product_id"]:
                if sig.indicator.lower() == device.product_id.lower():
                    matched.append(f"Product ID match: {sig.description}")
                    threat_score = max(threat_score, severity_scores.get(sig.severity, 50))

        # Check device class
        if "device_class" in self._signatures_cache and device.device_class:
            for sig in self._signatures_cache["device_class"]:
                if sig.indicator.lower() == device.device_class.lower():
                    matched.append(f"Device class match: {sig.description}")
                    threat_score = max(threat_score, severity_scores.get(sig.severity, 50))

        # Check serial number
        if "serial_number" in self._signatures_cache and device.serial_number:
            for sig in self._signatures_cache["serial_number"]:
                if sig.indicator.lower() in device.serial_number.lower():
                    matched.append(f"Serial number match: {sig.description}")
                    threat_score = max(threat_score, severity_scores.get(sig.severity, 50))

        # Check device name
        if "device_name" in self._signatures_cache and device.device_name:
            for sig in self._signatures_cache["device_name"]:
                if sig.indicator.lower() in device.device_name.lower():
                    matched.append(f"Device name match: {sig.description}")
                    threat_score = max(threat_score, severity_scores.get(sig.severity, 50))

        is_threat = len(matched) > 0
        return is_threat, threat_score, matched

    def add_signature(self, signature: ThreatSignature) -> bool:
        """Add new signature to database.

        Args:
            signature: ThreatSignature to add

        Returns:
            True if successful
        """
        try:
            self.db_manager.add_signature(signature)
            self.reload_signatures()
            return True
        except Exception as e:
            logger.error(f"Error adding signature: {e}")
            return False

    def get_statistics(self) -> Dict[str, int]:
        """Get signature statistics.

        Returns:
            Dictionary with signature counts by type
        """
        stats = {}
        for sig_type, sigs in self._signatures_cache.items():
            stats[sig_type] = len(sigs)
        return stats
