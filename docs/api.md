# USB Threat Detection - API Documentation

## Core APIs

### Database Manager

```python
from src.database.models import DatabaseManager, USBEvent, ThreatSignature

# Initialize
db = DatabaseManager("usb_threat_detection.db", wal_mode=True)

# Add event
event = USBEvent(
    event_type="connected",
    vendor_id="0x1234",
    product_id="0x5678",
    device_name="USB Device",
    is_threat=False,
    threat_score=0
)
event_id = db.add_event(event)

# Query events
recent_events = db.get_recent_events(limit=100)
threat_events = db.get_threat_events(limit=50)

# Manage signatures
signature = ThreatSignature(
    signature_type="vid_pid",
    indicator="0x1234:0x5678",
    description="Known malicious device",
    severity="high",
    source="custom"
)
sig_id = db.add_signature(signature)
signatures = db.get_signatures(signature_type="vid_pid")

# Whitelist operations
from src.database.models import WhitelistEntry

entry = WhitelistEntry(
    vendor_id="0xabcd",
    product_id="0xef01",
    description="Trusted device"
)
db.add_whitelist_entry(entry)
is_safe = db.is_whitelisted("0xabcd", "0xef01")
```

### USB Monitoring

```python
from src.monitors import get_platform_monitor
from src.monitors.base_monitor import USBDevice

# Get platform-specific monitor
monitor = get_platform_monitor()

if monitor and monitor.is_available():
    # Set callbacks
    def on_connected(device: USBDevice):
        print(f"Connected: {device.device_name}")

    def on_disconnected(device: USBDevice):
        print(f"Disconnected: {device.device_name}")

    monitor.set_connected_callback(on_connected)
    monitor.set_disconnected_callback(on_disconnected)

    # Start monitoring
    monitor.start_monitoring()

    # Get current devices
    devices = monitor.get_connected_devices()
    for device in devices:
        print(f"{device.get_vid_pid()}: {device.device_name}")

    # Stop monitoring
    monitor.stop_monitoring()
```

### Threat Detection

```python
from src.detectors import ThreatEngine
from src.database.models import DatabaseManager

db = DatabaseManager("usb_threat_detection.db")
engine = ThreatEngine(
    db_manager=db,
    enable_signatures=True,
    enable_heuristics=True,
    alert_threshold=50
)

# Analyze device
from src.monitors.base_monitor import USBDevice

device = USBDevice(
    vendor_id="0x1234",
    product_id="0x5678",
    device_name="Test Device"
)

result = engine.analyze_device(device)
print(f"Threat: {result.is_threat}")
print(f"Score: {result.threat_score}")
print(f"Details: {result.details}")

# Reload signatures
engine.reload_signatures()

# Get statistics
stats = engine.get_statistics()
```

### Feed Integration

```python
from src.feed_integration import FeedIntegration
from src.database.models import DatabaseManager

db = DatabaseManager("usb_threat_detection.db")
feed = FeedIntegration(db, verify_ssl=True, timeout=30)

# Check availability
if feed.is_available():
    # Update feeds
    sources = [
        {
            "name": "Example Feed",
            "url": "https://example.com/feed.json",
            "format": "json",
            "enabled": True
        }
    ]

    result = feed.update_all_feeds(sources)
    print(f"Updated: {result['feeds_updated']}")
    print(f"Signatures added: {result['signatures_added']}")

    # Get status
    status = feed.get_feed_status()
    print(status)
```

### Configuration

```python
from src.config import ConfigManager

# Load configuration
config = ConfigManager("config/default_config.yaml")

# Get values
db_path = config.get("database.path")
log_level = config.get("logging.level", "INFO")

# Get entire section
db_config = config.get_section("database")

# Set value
config.set("detection.alert_threshold", 60)

# Save configuration
config.save_config("custom_config.yaml")

# Setup logging
config.setup_logging()

# Validate
if config.validate():
    print("Configuration is valid")
```

## Data Models

### USBDevice

```python
@dataclass
class USBDevice:
    vendor_id: str          # VID in hex format (0x1234)
    product_id: str         # PID in hex format (0x5678)
    serial_number: str      # Device serial number
    device_name: str        # Human-readable name
    manufacturer: str       # Manufacturer name
    device_class: str       # USB device class
    mount_point: str        # Filesystem mount point
    device_path: str        # System device path
    bus_number: int         # USB bus number
    device_number: int      # Device number on bus
    speed: str              # USB speed
    extra_info: Dict        # Additional platform-specific info

    def get_vid_pid(self) -> str:
        """Returns VID:PID string"""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
```

### USBEvent

```python
class USBEvent:
    event_id: int
    timestamp: datetime
    event_type: str             # 'connected', 'disconnected'
    vendor_id: str
    product_id: str
    serial_number: str
    device_name: str
    manufacturer: str
    is_threat: bool
    threat_score: int           # 0-100
    threat_details: str
    device_class: str
    mount_point: str
```

### ThreatSignature

```python
class ThreatSignature:
    signature_id: int
    signature_type: str         # 'vid_pid', 'file_hash', etc.
    indicator: str              # The actual indicator value
    description: str
    severity: str               # 'low', 'medium', 'high', 'critical'
    source: str                 # Feed source name
    created_at: datetime
    last_updated: datetime
    metadata: str
```

### ThreatResult

```python
@dataclass
class ThreatResult:
    device: USBDevice
    is_threat: bool
    threat_score: int           # 0-100
    signature_matches: List[str]
    heuristic_findings: List[str]
    details: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
```

## Custom Detection

### Adding Custom Signatures

```python
from src.database.models import DatabaseManager, ThreatSignature

db = DatabaseManager("usb_threat_detection.db")

# Add VID:PID signature
sig = ThreatSignature(
    signature_type="vid_pid",
    indicator="0x1234:0x5678",
    description="Known BadUSB device",
    severity="critical",
    source="manual"
)
db.add_signature(sig)

# Add device class signature
sig = ThreatSignature(
    signature_type="device_class",
    indicator="0x03",  # HID
    description="HID device (keyboard emulation)",
    severity="medium",
    source="manual"
)
db.add_signature(sig)
```

### Implementing Custom Detector

```python
from src.monitors.base_monitor import USBDevice
from typing import Tuple, List

class CustomDetector:
    def check_device(self, device: USBDevice) -> Tuple[bool, int, List[str]]:
        """
        Check device for threats.

        Returns:
            (is_threat, threat_score, findings)
        """
        findings = []
        score = 0

        # Custom detection logic
        if "suspicious" in device.device_name.lower():
            findings.append("Suspicious device name")
            score += 50

        is_threat = score >= 30
        return is_threat, score, findings

# Integrate with ThreatEngine
from src.detectors.threat_engine import ThreatEngine

# Extend ThreatEngine or use custom detector separately
```

## Event Callbacks

### Monitor Callbacks

```python
def on_device_connected(device: USBDevice):
    """Called when device connects"""
    print(f"Device connected: {device.device_name}")
    # Perform custom action

def on_device_disconnected(device: USBDevice):
    """Called when device disconnects"""
    print(f"Device disconnected: {device.device_name}")
    # Perform custom action

monitor.set_connected_callback(on_device_connected)
monitor.set_disconnected_callback(on_device_disconnected)
```

## Error Handling

All APIs raise exceptions on errors:

- `sqlite3.Error`: Database errors
- `RuntimeError`: Monitor initialization/operation errors
- `ImportError`: Missing dependencies
- `ValueError`: Invalid configuration
- `requests.RequestException`: Network errors (feed integration)

```python
try:
    monitor.start_monitoring()
except RuntimeError as e:
    print(f"Monitoring unavailable: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Thread Safety

- **Database**: Connection per operation (SQLite handles locking)
- **GUI**: Use Qt signals for cross-thread updates
- **Monitors**: Callbacks executed in monitor thread

```python
# Thread-safe GUI update
from PyQt5.QtCore import pyqtSignal, QObject

class Signals(QObject):
    device_connected = pyqtSignal(object)

signals = Signals()
signals.device_connected.connect(gui_update_function)

# In monitor callback
def on_connected(device):
    signals.device_connected.emit(device)
```

## Performance Tips

1. **Database**: Use batch operations for multiple inserts
2. **Monitoring**: Adjust scan interval for polling-based backends
3. **Heuristics**: Limit filesystem scan depth
4. **Feeds**: Use caching to avoid redundant requests

## Platform Differences

### Windows
- Requires pywin32, wmi
- Administrator privileges recommended
- Real-time WMI events

### Linux
- Requires pyudev (preferred) or pyusb (fallback)
- Root or udev rules for USB access
- Event-based or polling

### Future: macOS
- Will use IOKit framework
- Requires admin for certain operations
