"""Linux USB monitoring using pyudev or pyusb."""

import logging
import sys
from typing import List
from src.monitors.base_monitor import BaseMonitor, USBDevice

logger = logging.getLogger(__name__)


class LinuxMonitor(BaseMonitor):
    """Linux USB device monitor using pyudev or pyusb."""

    def __init__(self):
        """Initialize Linux monitor."""
        super().__init__()
        self._monitor_impl = None
        self._backend = None
        self._available = self._check_availability()

    def _check_availability(self) -> bool:
        """Check if Linux monitoring is available."""
        if not sys.platform.startswith("linux"):
            return False

        # Try pyudev first (preferred - event-based)
        try:
            import pyudev

            self._backend = "pyudev"
            logger.info("Using pyudev backend for USB monitoring")
            return True
        except ImportError:
            pass

        # Fall back to pyusb (polling-based)
        try:
            import usb.core

            self._backend = "pyusb"
            logger.info("Using pyusb backend for USB monitoring (polling mode)")
            return True
        except ImportError:
            pass

        logger.warning("No Linux USB monitoring backend available (install pyudev or pyusb)")
        return False

    def is_available(self) -> bool:
        """Check if Linux monitoring is available."""
        return self._available

    def start_monitoring(self):
        """Start monitoring USB devices."""
        if not self.is_available():
            raise RuntimeError("Linux monitoring not available")

        if self._is_running:
            logger.warning("Monitor already running")
            return

        if self._backend == "pyudev":
            self._start_pyudev_monitoring()
        elif self._backend == "pyusb":
            self._start_pyusb_monitoring()
        else:
            raise RuntimeError("No monitoring backend available")

        self._is_running = True
        logger.info(f"Linux USB monitoring started ({self._backend})")

    def stop_monitoring(self):
        """Stop monitoring USB devices."""
        self._is_running = False

        if self._backend == "pyudev" and self._monitor_impl:
            try:
                self._monitor_impl.stop()
            except Exception as e:
                logger.error(f"Error stopping pyudev monitor: {e}")

        logger.info("Linux USB monitoring stopped")

    def get_connected_devices(self) -> List[USBDevice]:
        """Get list of currently connected USB devices."""
        if not self.is_available():
            return []

        if self._backend == "pyudev":
            return self._get_devices_pyudev()
        elif self._backend == "pyusb":
            return self._get_devices_pyusb()
        else:
            return []

    # PyUdev implementation (event-based, preferred)

    def _start_pyudev_monitoring(self):
        """Start monitoring using pyudev."""
        import pyudev
        import threading

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="usb")

        self._monitor_impl = monitor

        def monitor_thread():
            """Background thread for udev event monitoring."""
            for device in iter(monitor.poll, None):
                if not self._is_running:
                    break

                try:
                    if device.action == "add":
                        usb_device = self._parse_pyudev_device(device)
                        if usb_device:
                            self._on_device_connected(usb_device)
                    elif device.action == "remove":
                        usb_device = self._parse_pyudev_device(device)
                        if usb_device:
                            self._on_device_disconnected(usb_device)
                except Exception as e:
                    logger.error(f"Error processing udev event: {e}")

        monitor.start()
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()

    def _get_devices_pyudev(self) -> List[USBDevice]:
        """Get connected devices using pyudev."""
        import pyudev

        devices = []
        context = pyudev.Context()

        try:
            for device in context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
                try:
                    usb_device = self._parse_pyudev_device(device)
                    if usb_device:
                        devices.append(usb_device)
                except Exception as e:
                    logger.debug(f"Error parsing device: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error listing devices: {e}")

        return devices

    def _parse_pyudev_device(self, device) -> USBDevice:
        """Parse pyudev device into USBDevice."""
        try:
            vid = device.get("ID_VENDOR_ID", "")
            pid = device.get("ID_MODEL_ID", "")
            serial = device.get("ID_SERIAL_SHORT", "")
            manufacturer = device.get("ID_VENDOR", "")
            model = device.get("ID_MODEL", "")
            device_path = device.device_path
            bus_num = int(device.get("BUSNUM", 0))
            dev_num = int(device.get("DEVNUM", 0))

            if vid:
                vid = f"0x{vid}"
            if pid:
                pid = f"0x{pid}"

            device_name = model or "Unknown Device"
            if manufacturer and model:
                device_name = f"{manufacturer} {model}"

            return USBDevice(
                vendor_id=vid,
                product_id=pid,
                serial_number=serial,
                device_name=device_name,
                manufacturer=manufacturer,
                device_path=device_path,
                bus_number=bus_num,
                device_number=dev_num,
                extra_info={
                    "subsystem": device.subsystem,
                    "devtype": device.device_type,
                },
            )

        except Exception as e:
            logger.debug(f"Error parsing pyudev device: {e}")
            return None

    # PyUSB implementation (polling-based, fallback)

    def _start_pyusb_monitoring(self):
        """Start monitoring using pyusb (polling)."""
        import threading
        import time

        def monitor_thread():
            """Background thread for polling USB devices."""
            previous_devices = set()

            while self._is_running:
                try:
                    current_devices = {
                        (d.vendor_id, d.product_id, d.serial_number)
                        for d in self.get_connected_devices()
                    }

                    # Detect new devices
                    new_devices = current_devices - previous_devices
                    for vid, pid, serial in new_devices:
                        devices = [
                            d
                            for d in self.get_connected_devices()
                            if d.vendor_id == f"0x{vid:04x}"
                            and d.product_id == f"0x{pid:04x}"
                            and d.serial_number == serial
                        ]
                        if devices:
                            self._on_device_connected(devices[0])

                    # Detect removed devices
                    removed_devices = previous_devices - current_devices
                    for vid, pid, serial in removed_devices:
                        # Create minimal device info for disconnection
                        device = USBDevice(
                            vendor_id=f"0x{vid:04x}",
                            product_id=f"0x{pid:04x}",
                            serial_number=serial,
                        )
                        self._on_device_disconnected(device)

                    previous_devices = current_devices

                except Exception as e:
                    logger.error(f"Error in pyusb monitoring: {e}")

                time.sleep(5)  # Poll every 5 seconds

        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()

    def _get_devices_pyusb(self) -> List[USBDevice]:
        """Get connected devices using pyusb."""
        import usb.core

        devices = []

        try:
            for dev in usb.core.find(find_all=True):
                try:
                    usb_device = self._parse_pyusb_device(dev)
                    if usb_device:
                        devices.append(usb_device)
                except Exception as e:
                    logger.debug(f"Error parsing device: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error listing USB devices: {e}")

        return devices

    def _parse_pyusb_device(self, device) -> USBDevice:
        """Parse pyusb device into USBDevice."""
        try:
            vid = f"0x{device.idVendor:04x}"
            pid = f"0x{device.idProduct:04x}"

            # Try to get string descriptors
            serial = ""
            manufacturer = ""
            product = ""

            try:
                if device.iSerialNumber:
                    serial = usb.util.get_string(device, device.iSerialNumber)
            except Exception:
                pass

            try:
                if device.iManufacturer:
                    manufacturer = usb.util.get_string(device, device.iManufacturer)
            except Exception:
                pass

            try:
                if device.iProduct:
                    product = usb.util.get_string(device, device.iProduct)
            except Exception:
                pass

            device_name = product or "Unknown Device"
            if manufacturer and product:
                device_name = f"{manufacturer} {product}"

            # Map speed
            speed_map = {
                usb.core.SPEED_LOW: "1.5 Mbps",
                usb.core.SPEED_FULL: "12 Mbps",
                usb.core.SPEED_HIGH: "480 Mbps",
                usb.core.SPEED_SUPER: "5 Gbps",
            }
            speed = speed_map.get(device.speed, "Unknown")

            return USBDevice(
                vendor_id=vid,
                product_id=pid,
                serial_number=serial,
                device_name=device_name,
                manufacturer=manufacturer,
                device_class=f"0x{device.bDeviceClass:02x}",
                bus_number=device.bus,
                device_number=device.address,
                speed=speed,
                extra_info={
                    "device_class": device.bDeviceClass,
                    "device_subclass": device.bDeviceSubClass,
                    "device_protocol": device.bDeviceProtocol,
                },
            )

        except Exception as e:
            logger.debug(f"Error parsing pyusb device: {e}")
            return None


# Fix import for pyusb
try:
    import usb.util
except ImportError:
    pass
