"""Unit tests for database module."""

import pytest
import os
import tempfile
from datetime import datetime

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.models import DatabaseManager, USBEvent, ThreatSignature, WhitelistEntry


@pytest.fixture
def db_manager():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    db = DatabaseManager(db_path)
    yield db

    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


def test_database_initialization(db_manager):
    """Test database initializes correctly."""
    assert db_manager is not None
    assert os.path.exists(db_manager.db_path)


def test_add_usb_event(db_manager):
    """Test adding USB event."""
    event = USBEvent(
        event_type="connected",
        vendor_id="0x1234",
        product_id="0x5678",
        device_name="Test Device",
        manufacturer="Test Manufacturer",
        serial_number="TEST123",
    )

    event_id = db_manager.add_event(event)
    assert event_id > 0


def test_get_recent_events(db_manager):
    """Test retrieving recent events."""
    # Add test events
    for i in range(5):
        event = USBEvent(
            event_type="connected",
            vendor_id=f"0x{i:04x}",
            product_id="0x5678",
            device_name=f"Device {i}",
        )
        db_manager.add_event(event)

    # Retrieve events
    events = db_manager.get_recent_events(limit=10)
    assert len(events) == 5


def test_add_threat_signature(db_manager):
    """Test adding threat signature."""
    signature = ThreatSignature(
        signature_type="vid_pid",
        indicator="0x1234:0x5678",
        description="Test malicious device",
        severity="high",
        source="test",
    )

    sig_id = db_manager.add_signature(signature)
    assert sig_id > 0


def test_get_signatures(db_manager):
    """Test retrieving signatures."""
    # Add test signatures
    for i in range(3):
        sig = ThreatSignature(
            signature_type="vid_pid",
            indicator=f"0x{i:04x}:0x5678",
            description=f"Test signature {i}",
            severity="medium",
            source="test",
        )
        db_manager.add_signature(sig)

    # Retrieve signatures
    signatures = db_manager.get_signatures()
    assert len(signatures) >= 3


def test_whitelist_operations(db_manager):
    """Test whitelist operations."""
    # Add to whitelist
    entry = WhitelistEntry(
        vendor_id="0x1234",
        product_id="0x5678",
        serial_number="SAFE123",
        description="Safe device",
    )

    entry_id = db_manager.add_whitelist_entry(entry)
    assert entry_id > 0

    # Check if whitelisted
    assert db_manager.is_whitelisted("0x1234", "0x5678", "SAFE123")
    assert not db_manager.is_whitelisted("0x9999", "0x8888", "")

    # Get whitelist
    whitelist = db_manager.get_whitelist()
    assert len(whitelist) >= 1

    # Remove from whitelist
    assert db_manager.remove_whitelist_entry(entry_id)
    assert not db_manager.is_whitelisted("0x1234", "0x5678", "SAFE123")


def test_get_statistics(db_manager):
    """Test database statistics."""
    # Add some test data
    event = USBEvent(
        event_type="connected", vendor_id="0x1234", product_id="0x5678", is_threat=True
    )
    db_manager.add_event(event)

    stats = db_manager.get_statistics()
    assert "total_events" in stats
    assert "threat_events" in stats
    assert stats["total_events"] > 0
