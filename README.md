USB Threat Detection — How to Run

Overview
This repository contains a professional USB Threat Detection system with an optional threat‑intelligence feed integration. You can run it in two ways:
- Headless smoke test (no GUI, no network): quick validation that everything imports and the database initializes.
- Full GUI application: launches the desktop app for interactive monitoring (will run in Demo Mode if your platform dependencies are missing).

Which script do I run?
- Quick test (recommended first):
  python3 smoke_test.py
  What it does:
  - Does NOT launch a GUI.
  - Avoids real network calls to threat feeds.
  - Verifies the database and integration initialize correctly.
  - Prints a short status and exits.

- Full application (GUI):
  python3 ThreatDetectionSoftware.py
  What it does:
  - Launches the full desktop GUI.
  - Starts USB monitoring if platform support is available.
  - Falls back to Demo Mode when platform monitoring modules are not installed.

- Do NOT run directly:
  feed_integration.py
  This file is a library/integration module used by the main GUI and the smoke test. It is not intended to be executed on its own.

Dependencies and behavior
- Cross‑platform base: Python 3.8+.
- Linux USB monitoring:
  Option A (recommended fallback when pyudev is hard to install):
    pip install pyusb psutil
    Notes: The pyusb backend uses polling (no udev hotplug). It detects add/remove within the scan interval and may require libusb permissions for detailed attributes.
  Option B (original backend):
    pip install pyudev psutil
    Notes: The pyudev backend receives hotplug events from udev and can provide richer metadata.
- Windows USB monitoring:
  pip install pywin32 wmi
- Threat feed integration (optional):
  pip install requests certifi
  Optional ecosystems (only if you need them):
  - MISP: pip install pymisp
  - STIX 2: pip install stix2

Notes:
- The smoke test will run even if optional packages like requests, certifi, or pymisp are missing. It stubs network calls and avoids starting any GUI.
- The GUI app will still start in Demo Mode if platform monitoring modules are not installed; you can simulate events via the UI.

Automatic dependency installation (optional)
- If platform‑specific USB monitoring libraries are missing, the GUI will offer to install them for you at startup:
  - Windows: pywin32, wmi
  - Linux: pyusb (or pyudev), psutil
- If you accept, it runs pip install (user‑scoped on Linux) and relaunches the app. If the install fails or you decline, the app continues in Demo Mode.
- Packaged EXE note: Inside a PyInstaller EXE, pip is typically unavailable at runtime. For end‑users of the EXE, preinstall the dependencies and rebuild the EXE, or use the provided EXE built on a machine with these dependencies present.

Database and logs
- Default SQLite DB: usb_threat_detection.db (created in the project root)
- Default log file: usb_detection.log

Build a Windows EXE (PyInstaller)
Prerequisites on Windows:
- Python 3.8–3.12 (64‑bit recommended)
- pip install pyinstaller pywin32 wmi requests certifi
- Optional (for feeds): pip install pymisp stix2

Option A — One-command build (recommended):
  build_windows.bat
This script calls PyInstaller with the included spec file.

Option B — Use the spec file directly:
  pyinstaller USBThreatDetection.spec

Option C — Manual command (no spec):
  pyinstaller --noconfirm --windowed \
    --name USBThreatDetection \
    --add-data "usb_threat_detection.db;." \
    --add-data "usb_detection.log;." \
    --hidden-import win32timezone \
    --hidden-import win32com.client \
    --hidden-import feed_integration \
    ThreatDetectionSoftware.py

Notes for building:
- --windowed prevents a console window. Omit it if you want console logs.
- The hidden imports help PyInstaller discover dynamic modules used by pywin32/wmi and the integration.
- If you use threat feeds, ensure requests/certifi are included. Network access may be required at runtime.
- Run the resulting USBThreatDetection.exe from dist/USBThreatDetection.

Runtime detection on Windows
- USB detection requires admin privileges for full functionality. Right‑click the EXE and “Run as administrator”.
- The app will monitor USB events via WMI and pywin32 when available. If modules are missing or privileges are insufficient, the app falls back to Demo Mode.
- Malicious device detection comes from two sources:
  1) Built‑in signatures and heuristics (e.g., suspicious device classes, known bad VIDs/PIDs, risky autorun/file patterns).
  2) Threat feeds (optional): indicators like malicious file hashes, filenames, network indicators are converted to detection signatures.
- Detection is best‑effort. Without relevant signatures/indicators that match the specific malicious USB’s behavior/content, it may not flag it. Keeping feeds updated improves coverage.

Typical workflows
1) Validate setup quickly (no GUI, safe, offline):
   python3 smoke_test.py

2) Run the full GUI application (Windows):
   double‑click USBThreatDetection.exe (or run python3 ThreatDetectionSoftware.py)
   - If USB monitoring isn’t available, it will inform you and run in Demo Mode.

Troubleshooting
- ImportError: requests or certifi when running the GUI
  pip install requests certifi
  (The smoke test will not require these.)

- Linux: Monitoring unavailable
  pip install pyusb psutil  # fallback backend
  (Alternatively: pip install pyudev psutil)

- Windows: Monitoring unavailable or no events
  pip install pywin32 wmi; then rebuild the EXE
  Ensure you run as administrator

- Network errors while feeds are updating
  That’s normal offline or in restricted environments. The app uses caching when possible; the smoke test explicitly avoids network.

Support summary
- For a quick "Does it run?": run smoke_test.py
- For the full application: run ThreatDetectionSoftware.py (or the built EXE on Windows)
- Do not run feed_integration.py directly.
