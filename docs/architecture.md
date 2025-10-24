# USB Threat Detection - Architecture

## Overview

USB Threat Detection is a modular Python application designed to monitor USB devices and detect potential security threats using signature-based and heuristic analysis.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        GUI Layer                             │
│                    (PyQt5 Main Window)                       │
└───────────────┬─────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Threat     │  │    Feed      │  │   Config     │      │
│  │   Engine     │  │ Integration  │  │   Manager    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────┬──────────────────┬──────────────────┬──────────────┘
         │                  │                  │
┌────────▼────────┐ ┌───────▼────────┐ ┌──────▼──────────────┐
│   Detection     │ │   Database     │ │   USB Monitors      │
│   Engines       │ │   Layer        │ │  (Platform-Specific)│
│                 │ │                │ │                     │
│ • Signature     │ │ • Events       │ │ • Windows (WMI)    │
│ • Heuristic     │ │ • Signatures   │ │ • Linux (udev/usb) │
│                 │ │ • Whitelist    │ │                     │
└─────────────────┘ └────────────────┘ └─────────────────────┘
```

## Component Details

### 1. GUI Layer (`src/gui/`)

**Main Window** (`main_window.py`)
- PyQt5-based desktop application
- Real-time device monitoring display
- Event logging and threat visualization
- Configuration management interface

**Features:**
- Connected devices table
- Event log with threat highlighting
- Threat detection alerts
- Statistics dashboard
- System tray integration
- Demo mode for testing

### 2. Application Layer

**Threat Engine** (`src/detectors/threat_engine.py`)
- Coordinates detection engines
- Combines signature and heuristic analysis
- Manages whitelist checking
- Calculates threat scores

**Feed Integration** (`src/feed_integration.py`)
- Fetches threat intelligence from external sources
- Supports STIX 2.0, MISP, and custom JSON feeds
- Caches feed data with TTL
- Updates signature database

**Configuration Manager** (`src/config.py`)
- Loads YAML configuration files
- Provides configuration access API
- Validates settings
- Manages logging setup

### 3. Detection Engines (`src/detectors/`)

**Signature Detector** (`signature_detector.py`)
- Matches devices against known threat signatures
- Checks VID/PID combinations
- Identifies malicious device classes
- Database-driven signature management

**Heuristic Detector** (`heuristic_detector.py`)
- Analyzes device characteristics
- Detects suspicious patterns
- Scans filesystem for malicious files
- Identifies spoofing attempts

Detection rules:
- Missing manufacturer/device info
- Suspicious device classes (HID, mass storage)
- Sequential or pattern-based VID/PID
- Missing serial numbers
- Autorun.inf presence
- Hidden executables
- Double file extensions

### 4. Database Layer (`src/database/`)

**Database Manager** (`models.py`)
- SQLite-based persistence
- WAL mode for concurrency
- Indexed queries for performance

**Models:**
- `USBEvent`: Device connection/disconnection events
- `ThreatSignature`: Detection signatures from feeds
- `WhitelistEntry`: Trusted devices

### 5. USB Monitors (`src/monitors/`)

**Base Monitor** (`base_monitor.py`)
- Abstract interface for platform-specific implementations
- Callback-based event notification
- Device enumeration API

**Windows Monitor** (`windows_monitor.py`)
- WMI event-based monitoring
- Real-time device insertion/removal detection
- Parses PnP device information

**Linux Monitor** (`linux_monitor.py`)
- Dual backend support:
  - pyudev: Event-based (preferred)
  - pyusb: Polling-based (fallback)
- Hotplug event handling
- Device attribute extraction

## Data Flow

### Device Connection Flow

```
1. USB Device Connected
   ↓
2. Platform Monitor detects event
   ↓
3. Monitor extracts device information
   ↓
4. Callback triggers in Main Window
   ↓
5. Threat Engine analyzes device
   ├─→ Check Whitelist (if enabled)
   ├─→ Signature Detection
   └─→ Heuristic Analysis
   ↓
6. Combine scores and determine threat
   ↓
7. Create USBEvent in database
   ↓
8. Update GUI
   ├─→ Device list
   ├─→ Event log
   └─→ Threat notification (if applicable)
```

### Feed Update Flow

```
1. User triggers feed update / Scheduled update
   ↓
2. Feed Integration fetches from sources
   ├─→ STIX 2.0 feeds
   ├─→ MISP instances
   └─→ Custom JSON feeds
   ↓
3. Parse indicators based on format
   ↓
4. Convert to ThreatSignature objects
   ↓
5. Store in database
   ↓
6. Reload signatures in Threat Engine
   ↓
7. Update GUI statistics
```

## Threading Model

- **Main Thread**: GUI event loop (PyQt5)
- **Monitor Thread**: USB device monitoring (daemon)
- **Worker Threads**: Feed updates, file scanning

**Thread Safety:**
- Qt signals for cross-thread communication
- Database connection per operation (SQLite)
- Lock-free where possible (immutable data)

## Configuration

Configuration is hierarchical:
1. Built-in defaults (`ConfigManager.DEFAULT_CONFIG`)
2. System config (`/etc/usb-threat-detection/config.yaml`)
3. User config (`~/.config/usb-threat-detection/config.yaml`)
4. Explicit config file

Settings can be overridden at runtime through GUI.

## Security Considerations

1. **Privilege Escalation**
   - Windows: Administrator for WMI
   - Linux: Root or udev rules for USB access
   - Principle of least privilege applied

2. **Input Validation**
   - All external data sanitized
   - Threat feed data validated
   - SQL injection prevention (parameterized queries)

3. **Network Security**
   - TLS certificate verification
   - Configurable SSL validation
   - Request timeouts
   - No sensitive data transmitted

4. **Data Storage**
   - No credentials stored
   - Event logs rotated
   - Database access controlled by filesystem permissions

## Extensibility

The architecture supports extension in several ways:

1. **New Detection Methods**
   - Implement detector interface
   - Add to ThreatEngine

2. **Additional Feed Formats**
   - Add parser to FeedIntegration
   - Map to ThreatSignature format

3. **Platform Support**
   - Implement BaseMonitor for new OS
   - Add to platform detection

4. **Custom Signatures**
   - Define signature types
   - Add detection logic to SignatureDetector

## Performance Characteristics

- **Startup Time**: < 2 seconds
- **Device Detection Latency**:
  - Windows (WMI): Near real-time (< 500ms)
  - Linux (pyudev): Near real-time (< 500ms)
  - Linux (pyusb): Polling interval (default 5s)
- **Threat Analysis**: < 100ms per device
- **Database Operations**: < 10ms per query
- **Memory Usage**: ~50-100 MB (GUI mode)

## Deployment

### Standalone Executable
- PyInstaller bundles application
- Includes Python interpreter
- Platform-specific builds

### Python Package
- Installable via pip
- Entry points for scripts
- Optional dependencies for platforms

## Future Enhancements

1. **macOS Support**: Add Darwin monitor
2. **REST API**: Headless operation mode
3. **Advanced ML Detection**: Neural network classifiers
4. **Quarantine Actions**: Automated device blocking
5. **Cloud Integration**: Centralized management
6. **Real-time Collaboration**: Share threat data
