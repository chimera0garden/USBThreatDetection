"""Heuristic-based threat detection."""

import logging
import os
import hashlib
from typing import List, Tuple, Dict, Any
from src.monitors.base_monitor import USBDevice

logger = logging.getLogger(__name__)


class HeuristicDetector:
    """Heuristic-based USB threat detector."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize heuristic detector.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.scan_files = self.config.get("scan_files", True)
        self.max_scan_depth = self.config.get("max_scan_depth", 3)
        self.max_file_size = self.config.get("max_file_size", 100 * 1024 * 1024)  # 100MB

    def check_device(self, device: USBDevice) -> Tuple[bool, int, List[str]]:
        """Check device using heuristic analysis.

        Args:
            device: USB device to check

        Returns:
            Tuple of (is_threat, threat_score, findings)
        """
        findings = []
        threat_score = 0

        # Check 1: Missing manufacturer or device name (spoofing indicator)
        if not device.manufacturer or device.manufacturer in ["Unknown", ""]:
            findings.append("Missing manufacturer information (potential spoofing)")
            threat_score += 15

        if not device.device_name or device.device_name in ["Unknown Device", ""]:
            findings.append("Missing device name (potential spoofing)")
            threat_score += 10

        # Check 2: Suspicious device class combinations
        if device.device_class:
            device_class_int = int(device.device_class.replace("0x", ""), 16) if isinstance(
                device.device_class, str
            ) else device.device_class

            # HID device (keyboard emulation risk)
            if device_class_int == 0x03:
                findings.append("HID device detected (keyboard emulation risk)")
                threat_score += 25

            # Mass storage (autorun/malware risk)
            if device_class_int == 0x08:
                findings.append("Mass storage device (autorun/malware risk)")
                threat_score += 15

            # Hub device (unusual for typical USB devices)
            if device_class_int == 0x09:
                findings.append("USB hub device (potential for chaining attacks)")
                threat_score += 10

            # Wireless controller (networking risk)
            if device_class_int == 0xE0:
                findings.append("Wireless controller (network security risk)")
                threat_score += 20

        # Check 3: Suspicious vendor/product ID patterns
        if device.vendor_id and device.product_id:
            # Check for sequential or pattern-based IDs (common in DIY devices)
            try:
                vid_int = int(device.vendor_id.replace("0x", ""), 16)
                pid_int = int(device.product_id.replace("0x", ""), 16)

                # Sequential VID/PID (like 0x1234:0x5678 or 0x0000:0x0000)
                if abs(vid_int - pid_int) < 100 or (vid_int == 0 or pid_int == 0):
                    findings.append("Suspicious VID/PID pattern (possible DIY/modified device)")
                    threat_score += 20

            except (ValueError, AttributeError):
                pass

        # Check 4: Missing serial number (prevents tracking)
        if not device.serial_number or device.serial_number == "":
            findings.append("Missing serial number (prevents device tracking)")
            threat_score += 15

        # Check 5: Scan mounted filesystem if available
        if self.scan_files and device.mount_point:
            file_findings, file_score = self._scan_filesystem(device.mount_point)
            findings.extend(file_findings)
            threat_score += file_score

        is_threat = threat_score >= 30  # Threshold for heuristic detection
        return is_threat, min(threat_score, 100), findings

    def _scan_filesystem(self, mount_point: str) -> Tuple[List[str], int]:
        """Scan filesystem for suspicious files.

        Args:
            mount_point: Mount point to scan

        Returns:
            Tuple of (findings, threat_score)
        """
        findings = []
        threat_score = 0

        if not os.path.exists(mount_point) or not os.path.isdir(mount_point):
            return findings, threat_score

        try:
            # Check for autorun.inf (Windows autorun)
            autorun_path = os.path.join(mount_point, "autorun.inf")
            if os.path.exists(autorun_path):
                findings.append("Autorun.inf detected (Windows autorun risk)")
                threat_score += 30

            # Check for .lnk files in root (shortcut abuse)
            lnk_files = [
                f
                for f in os.listdir(mount_point)
                if f.lower().endswith(".lnk") and os.path.isfile(os.path.join(mount_point, f))
            ]
            if lnk_files:
                findings.append(f"Suspicious .lnk files detected: {len(lnk_files)}")
                threat_score += 20

            # Check for hidden executables
            hidden_exes = []
            for root, dirs, files in os.walk(mount_point):
                # Limit depth
                depth = root[len(mount_point):].count(os.sep)
                if depth >= self.max_scan_depth:
                    dirs[:] = []
                    continue

                for filename in files:
                    filepath = os.path.join(root, filename)

                    # Check if file is hidden and executable
                    try:
                        if filename.startswith(".") and filename.lower().endswith(
                            (".exe", ".bat", ".cmd", ".vbs", ".ps1", ".sh")
                        ):
                            hidden_exes.append(filename)

                        # Check for suspicious extensions
                        if filename.lower().endswith(
                            (".scr", ".pif", ".com", ".vbs", ".js", ".jse", ".wsf", ".wsh")
                        ):
                            findings.append(f"Suspicious file type: {filename}")
                            threat_score += 15

                    except (OSError, PermissionError):
                        pass

            if hidden_exes:
                findings.append(f"Hidden executables detected: {len(hidden_exes)}")
                threat_score += 25

            # Check for duplicate extensions (e.g., document.pdf.exe)
            for root, dirs, files in os.walk(mount_point):
                depth = root[len(mount_point):].count(os.sep)
                if depth >= self.max_scan_depth:
                    dirs[:] = []
                    continue

                for filename in files:
                    # Check for double extensions
                    parts = filename.split(".")
                    if len(parts) >= 3:  # At least two extensions
                        if parts[-1].lower() in ["exe", "bat", "cmd", "com", "scr"]:
                            findings.append(f"Double extension detected: {filename}")
                            threat_score += 20

        except Exception as e:
            logger.warning(f"Error scanning filesystem: {e}")

        return findings, min(threat_score, 100)

    def calculate_risk_score(self, device: USBDevice) -> int:
        """Calculate overall risk score for device.

        Args:
            device: USB device to evaluate

        Returns:
            Risk score (0-100)
        """
        _, score, _ = self.check_device(device)
        return score
