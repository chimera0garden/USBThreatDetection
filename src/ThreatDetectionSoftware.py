#!/usr/bin/env python3
"""
USB Threat Detection System - Main Application

This is the main entry point for the USB Threat Detection GUI application.
"""

import sys
import os
import logging

# Add src to path if running as script
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import ConfigManager
from src.database.models import DatabaseManager
from src.monitors import get_platform_monitor
from src.detectors import ThreatEngine
from src.feed_integration import FeedIntegration

logger = logging.getLogger(__name__)


def check_and_install_dependencies():
    """Check for platform-specific dependencies and offer to install."""
    import subprocess
    import platform

    missing_deps = []
    system = platform.system()

    # Check platform-specific dependencies
    if system == "Windows":
        try:
            import win32com.client
            import wmi
        except ImportError:
            missing_deps = ["pywin32", "wmi"]
    elif system == "Linux":
        try:
            import usb.core
        except ImportError:
            try:
                import pyudev
            except ImportError:
                missing_deps = ["pyusb"]

    if not missing_deps:
        return True

    # Ask user if they want to install
    print(f"\n{'=' * 60}")
    print("Missing Platform Dependencies")
    print(f"{'=' * 60}")
    print(f"\nThe following packages are required for USB monitoring on {system}:")
    for dep in missing_deps:
        print(f"  - {dep}")

    response = input("\nWould you like to install them now? (y/n): ").lower().strip()

    if response != "y":
        print("\nContinuing in Demo Mode (monitoring unavailable)...")
        return False

    # Install dependencies
    try:
        print("\nInstalling dependencies...")
        if system == "Linux":
            # Use --user for Linux to avoid permission issues
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user"] + missing_deps)
        else:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_deps)

        print("\nDependencies installed successfully!")
        print("Please restart the application for changes to take effect.")
        sys.exit(0)

    except subprocess.CalledProcessError as e:
        print(f"\nError installing dependencies: {e}")
        print("Continuing in Demo Mode...")
        return False


def main():
    """Main application entry point."""
    print("=" * 60)
    print("USB Threat Detection System v1.0.0")
    print("=" * 60)
    print()

    # Check dependencies first
    deps_available = check_and_install_dependencies()

    # Load configuration
    print("Loading configuration...")
    config_manager = ConfigManager("config/default_config.yaml")

    # Setup logging
    config_manager.setup_logging()
    logger.info("Starting USB Threat Detection System")

    # Validate configuration
    if not config_manager.validate():
        logger.error("Configuration validation failed")
        print("\nError: Configuration validation failed. Check logs for details.")
        sys.exit(1)

    # Initialize database
    print("Initializing database...")
    db_config = config_manager.get_section("database")
    db_manager = DatabaseManager(
        db_path=db_config.get("path", "usb_threat_detection.db"),
        wal_mode=db_config.get("wal_mode", True),
    )

    # Initialize USB monitor
    print("Initializing USB monitor...")
    monitor = get_platform_monitor()
    demo_mode = False

    if not monitor or not monitor.is_available():
        print("\n⚠️  WARNING: USB monitoring not available on this platform")
        print("   The application will run in Demo Mode")
        print("   Use 'Simulate Device' button to test functionality\n")
        demo_mode = True
        logger.warning("Running in Demo Mode - monitoring unavailable")

    # Initialize threat detection engine
    print("Initializing threat detection engine...")
    detection_config = config_manager.get_section("detection")
    threat_engine = ThreatEngine(
        db_manager=db_manager,
        config=config_manager.to_dict(),
        enable_signatures=detection_config.get("enable_signatures", True),
        enable_heuristics=detection_config.get("enable_heuristics", True),
        alert_threshold=detection_config.get("alert_threshold", 50),
    )

    # Initialize feed integration
    print("Initializing threat feed integration...")
    feed_config = config_manager.get_section("feeds")
    security_config = config_manager.get_section("security")
    feed_integration = FeedIntegration(
        db_manager=db_manager,
        config=feed_config,
        verify_ssl=security_config.get("verify_ssl", True),
        timeout=feed_config.get("timeout", 30),
    )

    if not feed_integration.is_available():
        print("   Note: Threat feed integration unavailable (install requests/certifi)")
        logger.warning("Threat feed integration unavailable")

    # Initialize GUI
    print("Starting GUI...")

    try:
        from PyQt5.QtWidgets import QApplication
        from src.gui.main_window import MainWindow

        app = QApplication(sys.argv)
        app.setApplicationName("USB Threat Detection")

        window = MainWindow(
            db_manager=db_manager,
            monitor=monitor,
            threat_engine=threat_engine,
            feed_integration=feed_integration,
            config_manager=config_manager,
            demo_mode=demo_mode,
        )

        window.show()

        logger.info("Application started successfully")
        print("\nApplication started successfully!")
        print("=" * 60)

        sys.exit(app.exec_())

    except ImportError as e:
        logger.error(f"GUI unavailable: {e}")
        print(f"\nError: GUI unavailable - {e}")
        print("Please install PyQt5: pip install PyQt5")
        sys.exit(1)

    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        print(f"\nFatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
