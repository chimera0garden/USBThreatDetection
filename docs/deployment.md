# Deployment Guide

## Installation Methods

### Method 1: From Source (Recommended for Development)

```bash
# Clone repository
git clone https://github.com/chimera0garden/USBThreatDetection.git
cd USBThreatDetection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python src/ThreatDetectionSoftware.py

# Run smoke test
python tests/smoke_test.py
```

### Method 2: Using pip (Local Install)

```bash
# Install in development mode
pip install -e .

# Or install specific extras
pip install -e ".[windows]"  # Windows-specific deps
pip install -e ".[linux]"    # Linux-specific deps
pip install -e ".[threat-intel]"  # Threat intelligence deps
pip install -e ".[dev]"      # Development dependencies

# Run via entry point
usb-threat-detection
```

### Method 3: Standalone Executable

Download pre-built executables from GitHub Releases:
- Windows: `USBThreatDetection-Windows.zip`
- Linux: `USBThreatDetection-Linux.tar.gz`

Extract and run:
- Windows: Right-click `USBThreatDetection.exe` → Run as Administrator
- Linux: `sudo ./USBThreatDetection`

## Platform-Specific Setup

### Windows

**Requirements:**
- Windows 10 or later (64-bit recommended)
- Python 3.8-3.12 (if running from source)
- Administrator privileges

**Install Dependencies:**
```powershell
pip install pywin32 wmi requests certifi PyQt5
```

**Administrator Mode:**
USB monitoring requires WMI access. Always run as Administrator:
```powershell
# PowerShell (as Admin)
python src/ThreatDetectionSoftware.py
```

**Windows Defender:**
Add exception if needed:
1. Windows Security → Virus & threat protection
2. Manage settings → Exclusions
3. Add folder: `C:\path\to\USBThreatDetection`

### Linux

**Requirements:**
- Ubuntu 20.04+ / Fedora 34+ / Debian 11+
- Python 3.8-3.12
- Root access or udev rules

**Install Dependencies:**

Ubuntu/Debian:
```bash
sudo apt update
sudo apt install python3-pip python3-venv libusb-1.0-0
pip3 install --user pyusb psutil requests certifi PyQt5
```

Fedora:
```bash
sudo dnf install python3-pip python3-virtualenv libusb
pip3 install --user pyusb psutil requests certifi PyQt5
```

**Option 1: Run as Root (Simple)**
```bash
sudo python3 src/ThreatDetectionSoftware.py
```

**Option 2: udev Rules (Recommended)**

Create udev rule for USB access:
```bash
# Create rule file
sudo nano /etc/udev/rules.d/50-usb-threat-detection.rules
```

Add content:
```
# USB Threat Detection - Allow USB device access
SUBSYSTEM=="usb", MODE="0666"
```

Reload udev rules:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Now run without sudo:
```bash
python3 src/ThreatDetectionSoftware.py
```

**SELinux (Fedora/RHEL):**
If using SELinux, you may need to set context:
```bash
sudo semanage fcontext -a -t bin_t "/path/to/USBThreatDetection(/.*)?"
sudo restorecon -Rv /path/to/USBThreatDetection
```

### macOS (Future Support)

Currently not supported. Planned for future release.

## Building Executables

### Windows Executable

```powershell
# Install PyInstaller
pip install pyinstaller

# Build using script
cd build
.\build_windows.bat

# Output: build/dist/USBThreatDetection/USBThreatDetection.exe
```

**Manual Build:**
```powershell
pyinstaller --noconfirm --windowed `
  --name USBThreatDetection `
  --add-data "config/default_config.yaml;config" `
  --hidden-import win32timezone `
  --hidden-import win32com.client `
  src/ThreatDetectionSoftware.py
```

### Linux Executable

```bash
# Install PyInstaller
pip3 install pyinstaller

# Build using script
cd build
chmod +x build_linux.sh
./build_linux.sh

# Output: build/dist/USBThreatDetection/USBThreatDetection
```

**Manual Build:**
```bash
pyinstaller --noconfirm --windowed \
  --name USBThreatDetection \
  --add-data "config/default_config.yaml:config" \
  src/ThreatDetectionSoftware.py
```

## Configuration

### Default Configuration

Located at: `config/default_config.yaml`

Key settings:
```yaml
database:
  path: "usb_threat_detection.db"

logging:
  file: "usb_detection.log"
  level: "INFO"

detection:
  enable_signatures: true
  enable_heuristics: true
  alert_threshold: 50

feeds:
  enable: true
  sources: []
```

### Custom Configuration

Create custom config:
```bash
cp config/default_config.yaml config/custom_config.yaml
# Edit custom_config.yaml
```

Specify at runtime:
```python
from src.config import ConfigManager

config = ConfigManager("config/custom_config.yaml")
```

### Environment-Specific Configs

Development:
```yaml
logging:
  level: "DEBUG"

detection:
  alert_threshold: 30  # More sensitive
```

Production:
```yaml
logging:
  level: "WARNING"

detection:
  alert_threshold: 60  # Less false positives
```

## Database Setup

Database is created automatically on first run.

**Manual Initialization:**
```python
from src.database.models import DatabaseManager

db = DatabaseManager("usb_threat_detection.db")
# Tables created automatically
```

**Backup Database:**
```bash
# SQLite database is a single file
cp usb_threat_detection.db usb_threat_detection.db.backup
```

**Reset Database:**
```bash
rm usb_threat_detection.db
# Will be recreated on next run
```

## Threat Feed Configuration

### Example Feed Sources

```yaml
feeds:
  enable: true
  sources:
    # Custom JSON feed
    - name: "My Threat Feed"
      url: "https://example.com/threats.json"
      format: "json"
      enabled: true
      verify_ssl: true

    # STIX 2.0 feed
    - name: "STIX Feed"
      url: "https://example.com/stix2-bundle.json"
      format: "stix2"
      enabled: true

    # MISP instance
    - name: "MISP"
      url: "https://misp.example.com"
      format: "misp"
      api_key: "YOUR-API-KEY-HERE"
      enabled: false  # Disabled by default
```

### Custom JSON Feed Format

```json
{
  "indicators": [
    {
      "type": "vid_pid",
      "value": "0x1234:0x5678",
      "description": "Known malicious USB device",
      "severity": "high"
    },
    {
      "type": "file_hash",
      "value": "abc123...",
      "description": "Malware file hash",
      "severity": "critical"
    }
  ]
}
```

## Systemd Service (Linux)

Create service file:
```bash
sudo nano /etc/systemd/system/usb-threat-detection.service
```

Content:
```ini
[Unit]
Description=USB Threat Detection Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/usb-threat-detection
ExecStart=/usr/bin/python3 /opt/usb-threat-detection/src/ThreatDetectionSoftware.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable usb-threat-detection
sudo systemctl start usb-threat-detection
sudo systemctl status usb-threat-detection
```

## Docker Deployment (Experimental)

**Note:** USB device access in containers is complex and may not work reliably.

Dockerfile:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-update && apt-get install -y libusb-1.0-0

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "src/ThreatDetectionSoftware.py"]
```

Run:
```bash
docker build -t usb-threat-detection .

# Linux with --privileged for USB access
docker run -it --privileged \
  -v /dev/bus/usb:/dev/bus/usb \
  usb-threat-detection
```

## Monitoring & Logging

### Log Files

- **Application Log:** `usb_detection.log`
- **Event Database:** `usb_threat_detection.db`

### Log Rotation

Configured in `config/default_config.yaml`:
```yaml
logging:
  max_bytes: 10485760  # 10 MB
  backup_count: 5       # Keep 5 old files
```

### Monitoring Logs

```bash
# Tail logs
tail -f usb_detection.log

# Search for threats
grep "THREAT DETECTED" usb_detection.log

# Monitor with journalctl (systemd)
sudo journalctl -u usb-threat-detection -f
```

## Performance Tuning

### Reduce CPU Usage

```yaml
monitoring:
  scan_interval: 10  # Increase polling interval (Linux pyusb)
  max_scan_depth: 2  # Reduce filesystem scan depth

performance:
  max_workers: 2     # Reduce thread count
```

### Reduce Memory Usage

- Disable GUI: Run smoke test mode only
- Limit event history: Regular database cleanup
- Disable feed integration if not needed

### Increase Detection Speed

```yaml
monitoring:
  scan_interval: 1   # Faster polling
  enable_hotplug: true  # Use event-based monitoring

performance:
  max_workers: 8     # More parallel workers
```

## Security Hardening

1. **Run with Minimum Privileges**
   - Use udev rules instead of root (Linux)
   - Use standard user with UAC (Windows)

2. **Verify Feed Sources**
   ```yaml
   security:
     verify_ssl: true
   ```

3. **Restrict Network Access**
   - Firewall rules for outbound only
   - Whitelist feed URLs

4. **Protect Database**
   ```bash
   chmod 600 usb_threat_detection.db
   ```

5. **Regular Updates**
   ```bash
   git pull origin main
   pip install --upgrade -r requirements.txt
   ```

## Troubleshooting

See README.md "Troubleshooting" section for common issues.

**Additional Tips:**

- Check logs: `usb_detection.log`
- Run smoke test: `python tests/smoke_test.py`
- Verify permissions: Especially on Linux
- Check dependencies: `pip list`
- Test network: `ping` feed URLs

## Uninstallation

### From Source
```bash
# Remove files
rm -rf USBThreatDetection

# Remove virtual environment
rm -rf venv
```

### systemd Service
```bash
sudo systemctl stop usb-threat-detection
sudo systemctl disable usb-threat-detection
sudo rm /etc/systemd/system/usb-threat-detection.service
sudo systemctl daemon-reload
```

### Clean Data
```bash
rm usb_threat_detection.db
rm usb_detection.log
```
