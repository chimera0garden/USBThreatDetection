"""USB monitoring modules for different platforms."""

from src.monitors.base_monitor import BaseMonitor, USBDevice
from src.monitors.windows_monitor import WindowsMonitor
from src.monitors.linux_monitor import LinuxMonitor

__all__ = ["BaseMonitor", "USBDevice", "WindowsMonitor", "LinuxMonitor"]


def get_platform_monitor():
    """Get appropriate monitor for current platform.

    Returns:
        Platform-specific monitor instance or None if unsupported
    """
    import sys

    if sys.platform == "win32":
        return WindowsMonitor()
    elif sys.platform.startswith("linux"):
        return LinuxMonitor()
    else:
        return None
