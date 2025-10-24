"""Unit tests for detection engines."""

import pytest
import os
import tempfile
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.models import DatabaseManager
from src.detectors import SignatureDetector, HeuristicDetector, ThreatEngine
from src.monitors.base_monitor import USBDevice


@pytest.fixture
def db_manager():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    db = DatabaseManager(db_path)
    yield db

    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def signature_detector(db_manager):
    """Create signature detector."""
    return SignatureDetector(db_manager)


@pytest.fixture
def heuristic_detector():
    """Create heuristic detector."""
    return HeuristicDetector()


@pytest.fixture
def threat_engine(db_manager):
    """Create threat engine."""
    return ThreatEngine(db_manager)


def test_signature_detector_check_device(signature_detector):
    """Test signature-based detection."""
    # Test device with suspicious characteristics
    device = USBDevice(
        vendor_id="0x16c0",  # Common BadUSB vendor
        product_id="0x5678",
        device_name="Test Device",
        device_class="0x03",  # HID
    )

    is_threat, score, matches = signature_detector.check_device(device)
    # Should detect based on vendor ID and device class
    assert score > 0


def test_heuristic_detector_check_device(heuristic_detector):
    """Test heuristic-based detection."""
    # Device with suspicious characteristics
    device = USBDevice(
        vendor_id="0x1234",
        product_id="0x5678",
        device_name="",  # Missing name
        manufacturer="",  # Missing manufacturer
        serial_number="",  # Missing serial
        device_class="0x03",  # HID (keyboard emulation risk)
    )

    is_threat, score, findings = heuristic_detector.check_device(device)
    # Should detect missing info and HID class
    assert score > 0
    assert len(findings) > 0


def test_threat_engine_analyze_device(threat_engine):
    """Test threat engine analysis."""
    device = USBDevice(
        vendor_id="0x1234",
        product_id="0x5678",
        device_name="Test Device",
        manufacturer="Test",
    )

    result = threat_engine.analyze_device(device)

    assert result is not None
    assert hasattr(result, "is_threat")
    assert hasattr(result, "threat_score")
    assert hasattr(result, "device")
    assert result.device == device


def test_threat_engine_whitelist(threat_engine, db_manager):
    """Test whitelist functionality."""
    from src.database.models import WhitelistEntry

    device = USBDevice(
        vendor_id="0x1234",
        product_id="0x5678",
        device_name="Safe Device",
        serial_number="SAFE123",
    )

    # Add to whitelist
    entry = WhitelistEntry(
        vendor_id=device.vendor_id,
        product_id=device.product_id,
        serial_number=device.serial_number,
        description="Test safe device",
    )
    db_manager.add_whitelist_entry(entry)

    # Analyze device
    result = threat_engine.analyze_device(device, check_whitelist=True)

    # Should not be threat because it's whitelisted
    assert not result.is_threat
    assert result.threat_score == 0
