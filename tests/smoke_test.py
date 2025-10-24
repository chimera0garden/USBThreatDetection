#!/usr/bin/env python3
"""
Smoke Test for USB Threat Detection

Quick validation that everything imports and initializes correctly.
Does NOT launch GUI or make network calls.
"""

import sys
import os
import tempfile
import logging

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def test_imports():
    """Test that all modules can be imported."""
    logger.info("Testing imports...")

    try:
        from src.config import ConfigManager
        from src.database.models import DatabaseManager, USBEvent, ThreatSignature
        from src.monitors.base_monitor import BaseMonitor, USBDevice
        from src.detectors import SignatureDetector, HeuristicDetector, ThreatEngine
        from src.feed_integration import FeedIntegration

        logger.info("✓ All imports successful")
        return True

    except ImportError as e:
        logger.error(f"✗ Import failed: {e}")
        return False


def test_database():
    """Test database initialization."""
    logger.info("Testing database...")

    try:
        from src.database.models import DatabaseManager, USBEvent

        # Use temporary database
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        db = DatabaseManager(db_path)

        # Test adding an event
        event = USBEvent(
            event_type="connected",
            vendor_id="0x1234",
            product_id="0x5678",
            device_name="Test Device",
        )
        event_id = db.add_event(event)

        # Test reading events
        events = db.get_recent_events(limit=10)
        assert len(events) == 1, "Should have one event"
        assert events[0].vendor_id == "0x1234", "VID should match"

        # Cleanup
        os.unlink(db_path)

        logger.info("✓ Database test passed")
        return True

    except Exception as e:
        logger.error(f"✗ Database test failed: {e}")
        return False


def test_detection_engine():
    """Test threat detection engine."""
    logger.info("Testing detection engine...")

    try:
        from src.database.models import DatabaseManager
        from src.detectors import ThreatEngine
        from src.monitors.base_monitor import USBDevice

        # Use temporary database
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        db = DatabaseManager(db_path)
        engine = ThreatEngine(db, enable_signatures=True, enable_heuristics=True)

        # Test analyzing a device
        device = USBDevice(
            vendor_id="0x1234",
            product_id="0x5678",
            device_name="Test Device",
            manufacturer="Test Manufacturer",
        )

        result = engine.analyze_device(device)
        assert result is not None, "Should return result"
        assert hasattr(result, "is_threat"), "Should have is_threat attribute"
        assert hasattr(result, "threat_score"), "Should have threat_score attribute"

        # Cleanup
        os.unlink(db_path)

        logger.info("✓ Detection engine test passed")
        return True

    except Exception as e:
        logger.error(f"✗ Detection engine test failed: {e}")
        return False


def test_config():
    """Test configuration manager."""
    logger.info("Testing configuration...")

    try:
        from src.config import ConfigManager

        config = ConfigManager()

        # Test getting values
        db_path = config.get("database.path")
        assert db_path is not None, "Should have database path"

        log_level = config.get("logging.level")
        assert log_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        # Test validation
        assert config.validate(), "Config should validate"

        logger.info("✓ Configuration test passed")
        return True

    except Exception as e:
        logger.error(f"✗ Configuration test failed: {e}")
        return False


def test_feed_integration():
    """Test feed integration (without network calls)."""
    logger.info("Testing feed integration...")

    try:
        from src.database.models import DatabaseManager
        from src.feed_integration import FeedIntegration

        # Use temporary database
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        db = DatabaseManager(db_path)
        feed = FeedIntegration(db)

        # Test basic initialization
        status = feed.get_feed_status()
        assert status is not None, "Should return status"
        assert "available" in status, "Status should have 'available' key"

        # Cleanup
        os.unlink(db_path)

        logger.info("✓ Feed integration test passed")
        return True

    except Exception as e:
        logger.error(f"✗ Feed integration test failed: {e}")
        return False


def main():
    """Run all smoke tests."""
    print("=" * 60)
    print("USB Threat Detection - Smoke Test")
    print("=" * 60)
    print()

    tests = [
        ("Imports", test_imports),
        ("Database", test_database),
        ("Detection Engine", test_detection_engine),
        ("Configuration", test_config),
        ("Feed Integration", test_feed_integration),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        print(f"\nRunning: {test_name}")
        print("-" * 40)
        if test_func():
            passed += 1
        else:
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("\n✓ All smoke tests passed!")
        return 0
    else:
        print(f"\n✗ {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
