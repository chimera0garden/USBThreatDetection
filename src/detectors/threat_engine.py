"""Main threat detection engine combining multiple detectors."""

import logging
from dataclasses import dataclass
from typing import List, Dict, Any
from src.monitors.base_monitor import USBDevice
from src.detectors.signature_detector import SignatureDetector
from src.detectors.heuristic_detector import HeuristicDetector
from src.database.models import DatabaseManager

logger = logging.getLogger(__name__)


@dataclass
class ThreatResult:
    """Result of threat detection analysis."""

    device: USBDevice
    is_threat: bool
    threat_score: int
    signature_matches: List[str]
    heuristic_findings: List[str]
    details: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "device": self.device.to_dict(),
            "is_threat": self.is_threat,
            "threat_score": self.threat_score,
            "signature_matches": self.signature_matches,
            "heuristic_findings": self.heuristic_findings,
            "details": self.details,
        }


class ThreatEngine:
    """Main threat detection engine."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        config: Dict[str, Any] = None,
        enable_signatures: bool = True,
        enable_heuristics: bool = True,
        alert_threshold: int = 50,
    ):
        """Initialize threat detection engine.

        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
            enable_signatures: Enable signature-based detection
            enable_heuristics: Enable heuristic detection
            alert_threshold: Minimum threat score to trigger alert
        """
        self.db_manager = db_manager
        self.config = config or {}
        self.enable_signatures = enable_signatures
        self.enable_heuristics = enable_heuristics
        self.alert_threshold = alert_threshold

        # Initialize detectors
        self.signature_detector = (
            SignatureDetector(db_manager) if enable_signatures else None
        )
        self.heuristic_detector = (
            HeuristicDetector(config.get("monitoring", {})) if enable_heuristics else None
        )

        logger.info(
            f"Threat engine initialized (signatures={enable_signatures}, "
            f"heuristics={enable_heuristics}, threshold={alert_threshold})"
        )

    def analyze_device(self, device: USBDevice, check_whitelist: bool = True) -> ThreatResult:
        """Analyze device for threats.

        Args:
            device: USB device to analyze
            check_whitelist: Check against whitelist first

        Returns:
            ThreatResult object
        """
        # Check whitelist first
        if check_whitelist:
            if self.db_manager.is_whitelisted(
                device.vendor_id, device.product_id, device.serial_number
            ):
                logger.info(f"Device whitelisted: {device.get_vid_pid()}")
                return ThreatResult(
                    device=device,
                    is_threat=False,
                    threat_score=0,
                    signature_matches=[],
                    heuristic_findings=["Device is whitelisted"],
                    details="Device is whitelisted",
                )

        signature_matches = []
        heuristic_findings = []
        signature_score = 0
        heuristic_score = 0

        # Run signature detection
        if self.enable_signatures and self.signature_detector:
            try:
                sig_threat, sig_score, sig_matches = self.signature_detector.check_device(device)
                signature_score = sig_score
                signature_matches = sig_matches
            except Exception as e:
                logger.error(f"Error in signature detection: {e}")

        # Run heuristic detection
        if self.enable_heuristics and self.heuristic_detector:
            try:
                heur_threat, heur_score, heur_findings = self.heuristic_detector.check_device(
                    device
                )
                heuristic_score = heur_score
                heuristic_findings = heur_findings
            except Exception as e:
                logger.error(f"Error in heuristic detection: {e}")

        # Combine scores (weighted average, signatures count more)
        if self.enable_signatures and self.enable_heuristics:
            combined_score = int((signature_score * 0.6) + (heuristic_score * 0.4))
        elif self.enable_signatures:
            combined_score = signature_score
        elif self.enable_heuristics:
            combined_score = heuristic_score
        else:
            combined_score = 0

        # Determine if threat
        is_threat = combined_score >= self.alert_threshold

        # Build details string
        details_parts = []
        if signature_matches:
            details_parts.append(f"Signatures: {', '.join(signature_matches)}")
        if heuristic_findings:
            details_parts.append(f"Heuristics: {', '.join(heuristic_findings)}")
        details = " | ".join(details_parts) if details_parts else "No threats detected"

        result = ThreatResult(
            device=device,
            is_threat=is_threat,
            threat_score=combined_score,
            signature_matches=signature_matches,
            heuristic_findings=heuristic_findings,
            details=details,
        )

        # Log result
        if is_threat:
            logger.warning(
                f"THREAT DETECTED: {device.get_vid_pid()} - {device.device_name} "
                f"(score: {combined_score}) - {details}"
            )
        else:
            logger.info(f"Device OK: {device.get_vid_pid()} - {device.device_name}")

        return result

    def reload_signatures(self):
        """Reload threat signatures from database."""
        if self.signature_detector:
            self.signature_detector.reload_signatures()
            logger.info("Threat signatures reloaded")

    def get_statistics(self) -> Dict[str, Any]:
        """Get detection engine statistics.

        Returns:
            Dictionary with statistics
        """
        stats = {
            "signatures_enabled": self.enable_signatures,
            "heuristics_enabled": self.enable_heuristics,
            "alert_threshold": self.alert_threshold,
        }

        if self.signature_detector:
            stats["signature_stats"] = self.signature_detector.get_statistics()

        return stats
