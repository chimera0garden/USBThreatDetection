"""Base USB monitor interface."""

from abc import ABC, abstractmethod
from typing import List, Callable, Optional, Dict, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class USBDevice:
    """Represents a USB device."""

    vendor_id: str = ""
    product_id: str = ""
    serial_number: str = ""
    device_name: str = ""
    manufacturer: str = ""
    device_class: str = ""
    mount_point: str = ""
    device_path: str = ""
    bus_number: int = 0
    device_number: int = 0
    speed: str = ""
    extra_info: Dict[str, Any] = None

    def __post_init__(self):
        if self.extra_info is None:
            self.extra_info = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "device_name": self.device_name,
            "manufacturer": self.manufacturer,
            "device_class": self.device_class,
            "mount_point": self.mount_point,
            "device_path": self.device_path,
            "bus_number": self.bus_number,
            "device_number": self.device_number,
            "speed": self.speed,
            "extra_info": self.extra_info,
        }

    def get_vid_pid(self) -> str:
        """Get formatted VID:PID string."""
        return f"{self.vendor_id}:{self.product_id}"


class BaseMonitor(ABC):
    """Abstract base class for USB device monitoring."""

    def __init__(self):
        """Initialize monitor."""
        self.connected_callback: Optional[Callable[[USBDevice], None]] = None
        self.disconnected_callback: Optional[Callable[[USBDevice], None]] = None
        self._is_running = False
        self._available = False

    @abstractmethod
    def is_available(self) -> bool:
        """Check if monitoring is available on this platform.

        Returns:
            True if monitoring can be performed
        """
        pass

    @abstractmethod
    def start_monitoring(self):
        """Start monitoring USB devices.

        Raises:
            RuntimeError: If monitoring cannot be started
        """
        pass

    @abstractmethod
    def stop_monitoring(self):
        """Stop monitoring USB devices."""
        pass

    @abstractmethod
    def get_connected_devices(self) -> List[USBDevice]:
        """Get list of currently connected USB devices.

        Returns:
            List of USBDevice objects
        """
        pass

    def set_connected_callback(self, callback: Callable[[USBDevice], None]):
        """Set callback for device connection events.

        Args:
            callback: Function to call when device connects
        """
        self.connected_callback = callback

    def set_disconnected_callback(self, callback: Callable[[USBDevice], None]):
        """Set callback for device disconnection events.

        Args:
            callback: Function to call when device disconnects
        """
        self.disconnected_callback = callback

    def _on_device_connected(self, device: USBDevice):
        """Internal handler for device connection.

        Args:
            device: Connected device
        """
        logger.info(f"Device connected: {device.get_vid_pid()} - {device.device_name}")
        if self.connected_callback:
            try:
                self.connected_callback(device)
            except Exception as e:
                logger.error(f"Error in connected callback: {e}")

    def _on_device_disconnected(self, device: USBDevice):
        """Internal handler for device disconnection.

        Args:
            device: Disconnected device
        """
        logger.info(f"Device disconnected: {device.get_vid_pid()} - {device.device_name}")
        if self.disconnected_callback:
            try:
                self.disconnected_callback(device)
            except Exception as e:
                logger.error(f"Error in disconnected callback: {e}")

    @property
    def is_running(self) -> bool:
        """Check if monitor is currently running.

        Returns:
            True if monitoring is active
        """
        return self._is_running
