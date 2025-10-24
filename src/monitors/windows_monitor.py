"""Windows USB monitoring using WMI."""

import logging
import sys
from typing import List
from src.monitors.base_monitor import BaseMonitor, USBDevice

logger = logging.getLogger(__name__)


class WindowsMonitor(BaseMonitor):
    """Windows USB device monitor using WMI and pywin32."""

    def __init__(self):
        """Initialize Windows monitor."""
        super().__init__()
        self._watcher = None
        self._wmi = None
        self._available = self._check_availability()

    def _check_availability(self) -> bool:
        """Check if Windows monitoring is available."""
        if sys.platform != "win32":
            return False

        try:
            import wmi
            import win32com.client

            self._wmi = wmi.WMI()
            return True
        except ImportError as e:
            logger.warning(f"Windows monitoring unavailable: {e}")
            return False
        except Exception as e:
            logger.error(f"Error initializing Windows monitor: {e}")
            return False

    def is_available(self) -> bool:
        """Check if Windows monitoring is available."""
        return self._available

    def start_monitoring(self):
        """Start monitoring USB devices using WMI events."""
        if not self.is_available():
            raise RuntimeError("Windows monitoring not available")

        if self._is_running:
            logger.warning("Monitor already running")
            return

        try:
            import win32com.client
            import pythoncom
            import threading

            self._is_running = True

            def monitor_thread():
                """Background thread for WMI event monitoring."""
                pythoncom.CoInitialize()
                try:
                    # Monitor for USB device insertion
                    watcher_insert = self._wmi.watch_for(
                        notification_type="Creation",
                        wmi_class="Win32_USBControllerDevice",
                        delay_secs=1,
                    )

                    # Monitor for USB device removal
                    watcher_remove = self._wmi.watch_for(
                        notification_type="Deletion",
                        wmi_class="Win32_USBControllerDevice",
                        delay_secs=1,
                    )

                    while self._is_running:
                        try:
                            # Check for insertions (with timeout)
                            device = watcher_insert(timeout_ms=500)
                            if device:
                                usb_device = self._parse_wmi_device(device)
                                if usb_device:
                                    self._on_device_connected(usb_device)
                        except Exception:
                            pass

                        try:
                            # Check for removals (with timeout)
                            device = watcher_remove(timeout_ms=500)
                            if device:
                                usb_device = self._parse_wmi_device(device)
                                if usb_device:
                                    self._on_device_disconnected(usb_device)
                        except Exception:
                            pass

                except Exception as e:
                    logger.error(f"WMI monitoring error: {e}")
                finally:
                    pythoncom.CoUninitialize()

            thread = threading.Thread(target=monitor_thread, daemon=True)
            thread.start()

            logger.info("Windows USB monitoring started")

        except Exception as e:
            self._is_running = False
            logger.error(f"Failed to start Windows monitoring: {e}")
            raise RuntimeError(f"Failed to start monitoring: {e}")

    def stop_monitoring(self):
        """Stop monitoring USB devices."""
        self._is_running = False
        logger.info("Windows USB monitoring stopped")

    def get_connected_devices(self) -> List[USBDevice]:
        """Get list of currently connected USB devices."""
        if not self.is_available():
            return []

        devices = []
        try:
            # Query all USB devices
            for usb_device in self._wmi.Win32_USBControllerDevice():
                try:
                    dependent = usb_device.Dependent
                    if dependent:
                        device = self._parse_pnp_device(dependent)
                        if device:
                            devices.append(device)
                except Exception as e:
                    logger.debug(f"Error parsing device: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error getting connected devices: {e}")

        return devices

    def _parse_wmi_device(self, wmi_device) -> USBDevice:
        """Parse WMI device object into USBDevice.

        Args:
            wmi_device: WMI device object

        Returns:
            USBDevice object or None
        """
        try:
            dependent = wmi_device.Dependent
            return self._parse_pnp_device(dependent)
        except Exception as e:
            logger.debug(f"Error parsing WMI device: {e}")
            return None

    def _parse_pnp_device(self, pnp_device) -> USBDevice:
        """Parse PnP device into USBDevice.

        Args:
            pnp_device: Win32_PnPEntity object

        Returns:
            USBDevice object or None
        """
        try:
            device_id = getattr(pnp_device, "DeviceID", "")
            if not device_id or "USB" not in device_id.upper():
                return None

            # Parse VID and PID from DeviceID
            vid = ""
            pid = ""
            serial = ""

            if "VID_" in device_id:
                vid_start = device_id.index("VID_") + 4
                vid = device_id[vid_start:vid_start + 4]
                vid = f"0x{vid}"

            if "PID_" in device_id:
                pid_start = device_id.index("PID_") + 4
                pid = device_id[pid_start:pid_start + 4]
                pid = f"0x{pid}"

            # Try to extract serial number
            parts = device_id.split("\\")
            if len(parts) >= 3:
                serial = parts[2]

            device_name = getattr(pnp_device, "Name", "Unknown Device")
            manufacturer = getattr(pnp_device, "Manufacturer", "Unknown")
            device_class = getattr(pnp_device, "PNPClass", "")
            status = getattr(pnp_device, "Status", "")

            return USBDevice(
                vendor_id=vid,
                product_id=pid,
                serial_number=serial,
                device_name=device_name,
                manufacturer=manufacturer,
                device_class=device_class,
                device_path=device_id,
                extra_info={
                    "status": status,
                    "device_id": device_id,
                },
            )

        except Exception as e:
            logger.debug(f"Error parsing PnP device: {e}")
            return None
