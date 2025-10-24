"""Main GUI window for USB Threat Detection."""

import logging
import sys
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from PyQt5.QtWidgets import (
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QTableWidget,
        QTableWidgetItem,
        QPushButton,
        QLabel,
        QTextEdit,
        QTabWidget,
        QMessageBox,
        QHeaderView,
        QSystemTrayIcon,
        QMenu,
        QAction,
    )
    from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
    from PyQt5.QtGui import QIcon, QColor

    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False

logger = logging.getLogger(__name__)


class EventSignals(QObject) if PYQT5_AVAILABLE else object:
    """Signals for thread-safe GUI updates."""

    device_connected = pyqtSignal(object) if PYQT5_AVAILABLE else None
    device_disconnected = pyqtSignal(object) if PYQT5_AVAILABLE else None
    threat_detected = pyqtSignal(object) if PYQT5_AVAILABLE else None


class MainWindow(QMainWindow if PYQT5_AVAILABLE else object):
    """Main application window."""

    def __init__(
        self,
        db_manager,
        monitor,
        threat_engine,
        feed_integration,
        config_manager,
        demo_mode: bool = False,
    ):
        """Initialize main window.

        Args:
            db_manager: Database manager instance
            monitor: USB monitor instance
            threat_engine: Threat detection engine
            feed_integration: Feed integration manager
            config_manager: Configuration manager
            demo_mode: Whether running in demo mode
        """
        if not PYQT5_AVAILABLE:
            raise ImportError("PyQt5 is required for GUI mode")

        super().__init__()

        self.db_manager = db_manager
        self.monitor = monitor
        self.threat_engine = threat_engine
        self.feed_integration = feed_integration
        self.config_manager = config_manager
        self.demo_mode = demo_mode

        # GUI state
        self.monitoring_active = False
        self.signals = EventSignals()

        # Connect signals
        self.signals.device_connected.connect(self._on_device_connected_gui)
        self.signals.device_disconnected.connect(self._on_device_disconnected_gui)
        self.signals.threat_detected.connect(self._on_threat_detected_gui)

        # Setup UI
        self.init_ui()

        # Setup system tray if configured
        if self.config_manager.get("gui.show_tray_icon", True):
            self.setup_tray_icon()

        # Setup refresh timer
        refresh_interval = self.config_manager.get("gui.refresh_interval", 1000)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_device_list)
        self.refresh_timer.start(refresh_interval)

        logger.info(f"GUI initialized (demo_mode={demo_mode})")

    def init_ui(self):
        """Initialize user interface."""
        self.setWindowTitle("USB Threat Detection System")

        # Set window size from config
        width = self.config_manager.get("gui.window_width", 1024)
        height = self.config_manager.get("gui.window_height", 768)
        self.resize(width, height)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Status bar
        self.status_label = QLabel("Status: Initializing...")
        main_layout.addWidget(self.status_label)

        # Demo mode warning
        if self.demo_mode:
            demo_label = QLabel(
                "⚠️ DEMO MODE: Platform monitoring unavailable. "
                "Use 'Simulate Device' for testing."
            )
            demo_label.setStyleSheet("background-color: #fff3cd; padding: 10px;")
            main_layout.addWidget(demo_label)

        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self.toggle_monitoring)
        button_layout.addWidget(self.start_btn)

        self.refresh_btn = QPushButton("Refresh Devices")
        self.refresh_btn.clicked.connect(self.refresh_device_list)
        button_layout.addWidget(self.refresh_btn)

        self.update_feeds_btn = QPushButton("Update Threat Feeds")
        self.update_feeds_btn.clicked.connect(self.update_feeds)
        button_layout.addWidget(self.update_feeds_btn)

        if self.demo_mode:
            self.simulate_btn = QPushButton("Simulate Device Connection")
            self.simulate_btn.clicked.connect(self.simulate_device)
            button_layout.addWidget(self.simulate_btn)

        button_layout.addStretch()
        main_layout.addLayout(button_layout)

        # Tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Connected Devices tab
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(6)
        self.devices_table.setHorizontalHeaderLabels(
            ["Vendor ID", "Product ID", "Device Name", "Manufacturer", "Serial", "Status"]
        )
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tab_widget.addTab(self.devices_table, "Connected Devices")

        # Event Log tab
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.tab_widget.addTab(self.event_log, "Event Log")

        # Threats tab
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(5)
        self.threats_table.setHorizontalHeaderLabels(
            ["Time", "Device", "Threat Score", "Details", "Action"]
        )
        self.threats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tab_widget.addTab(self.threats_table, "Detected Threats")

        # Statistics tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.tab_widget.addTab(self.stats_text, "Statistics")

        # Update status
        self.update_status()
        self.update_statistics()

    def setup_tray_icon(self):
        """Setup system tray icon."""
        try:
            self.tray_icon = QSystemTrayIcon(self)
            # Note: In production, use a proper icon file
            # self.tray_icon.setIcon(QIcon("icon.png"))

            tray_menu = QMenu()
            show_action = QAction("Show", self)
            show_action.triggered.connect(self.show)
            tray_menu.addAction(show_action)

            quit_action = QAction("Quit", self)
            quit_action.triggered.connect(self.close)
            tray_menu.addAction(quit_action)

            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()

        except Exception as e:
            logger.warning(f"Could not setup system tray: {e}")

    def toggle_monitoring(self):
        """Toggle USB monitoring on/off."""
        if not self.monitoring_active:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        """Start USB monitoring."""
        try:
            if self.demo_mode:
                self.log_event("Demo Mode: Monitoring simulation started")
                self.monitoring_active = True
                self.start_btn.setText("Stop Monitoring")
                self.update_status()
                return

            if not self.monitor or not self.monitor.is_available():
                QMessageBox.warning(
                    self,
                    "Monitoring Unavailable",
                    "USB monitoring is not available on this platform. "
                    "Please install required dependencies.",
                )
                return

            # Set callbacks
            self.monitor.set_connected_callback(self._on_device_connected)
            self.monitor.set_disconnected_callback(self._on_device_disconnected)

            # Start monitoring
            self.monitor.start_monitoring()
            self.monitoring_active = True
            self.start_btn.setText("Stop Monitoring")

            self.log_event("USB monitoring started")
            self.update_status()

        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start monitoring: {e}")

    def stop_monitoring(self):
        """Stop USB monitoring."""
        try:
            if not self.demo_mode and self.monitor:
                self.monitor.stop_monitoring()

            self.monitoring_active = False
            self.start_btn.setText("Start Monitoring")

            self.log_event("USB monitoring stopped")
            self.update_status()

        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")

    def _on_device_connected(self, device):
        """Callback for device connection (from monitoring thread).

        Args:
            device: Connected USB device
        """
        # Emit signal for thread-safe GUI update
        self.signals.device_connected.emit(device)

    def _on_device_disconnected(self, device):
        """Callback for device disconnection (from monitoring thread).

        Args:
            device: Disconnected USB device
        """
        # Emit signal for thread-safe GUI update
        self.signals.device_disconnected.emit(device)

    def _on_device_connected_gui(self, device):
        """Handle device connection in GUI thread.

        Args:
            device: Connected USB device
        """
        # Analyze device for threats
        result = self.threat_engine.analyze_device(device)

        # Log event to database
        from src.database.models import USBEvent

        event = USBEvent(
            event_type="connected",
            vendor_id=device.vendor_id,
            product_id=device.product_id,
            serial_number=device.serial_number,
            device_name=device.device_name,
            manufacturer=device.manufacturer,
            is_threat=result.is_threat,
            threat_score=result.threat_score,
            threat_details=result.details,
            device_class=device.device_class,
            mount_point=device.mount_point,
        )
        self.db_manager.add_event(event)

        # Update GUI
        self.log_event(
            f"Device connected: {device.device_name} ({device.get_vid_pid()})"
        )

        if result.is_threat:
            self.signals.threat_detected.emit(result)

        self.refresh_device_list()

    def _on_device_disconnected_gui(self, device):
        """Handle device disconnection in GUI thread.

        Args:
            device: Disconnected USB device
        """
        # Log event to database
        from src.database.models import USBEvent

        event = USBEvent(
            event_type="disconnected",
            vendor_id=device.vendor_id,
            product_id=device.product_id,
            serial_number=device.serial_number,
            device_name=device.device_name,
            manufacturer=device.manufacturer,
        )
        self.db_manager.add_event(event)

        # Update GUI
        self.log_event(
            f"Device disconnected: {device.device_name} ({device.get_vid_pid()})"
        )
        self.refresh_device_list()

    def _on_threat_detected_gui(self, result):
        """Handle threat detection in GUI thread.

        Args:
            result: ThreatResult object
        """
        device = result.device

        # Log threat
        self.log_event(
            f"⚠️ THREAT DETECTED: {device.device_name} ({device.get_vid_pid()}) "
            f"- Score: {result.threat_score} - {result.details}",
            is_threat=True,
        )

        # Add to threats table
        row = self.threats_table.rowCount()
        self.threats_table.insertRow(row)

        self.threats_table.setItem(row, 0, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self.threats_table.setItem(
            row, 1, QTableWidgetItem(f"{device.device_name} ({device.get_vid_pid()})")
        )

        score_item = QTableWidgetItem(str(result.threat_score))
        score_item.setBackground(QColor("#ff4444"))
        self.threats_table.setItem(row, 2, score_item)

        self.threats_table.setItem(row, 3, QTableWidgetItem(result.details[:100]))

        # Add whitelist button
        whitelist_btn = QPushButton("Whitelist")
        whitelist_btn.clicked.connect(lambda: self.whitelist_device(device))
        self.threats_table.setCellWidget(row, 4, whitelist_btn)

        # Show notification
        if self.config_manager.get("detection.enable_notifications", True):
            self.show_threat_notification(result)

    def show_threat_notification(self, result):
        """Show threat notification.

        Args:
            result: ThreatResult object
        """
        try:
            device = result.device
            message = (
                f"Threat detected: {device.device_name}\n"
                f"Score: {result.threat_score}\n"
                f"{result.details[:100]}"
            )

            if hasattr(self, "tray_icon") and self.tray_icon:
                self.tray_icon.showMessage(
                    "USB Threat Detected!", message, QSystemTrayIcon.Warning, 5000
                )
            else:
                QMessageBox.warning(self, "Threat Detected", message)

        except Exception as e:
            logger.error(f"Error showing notification: {e}")

    def refresh_device_list(self):
        """Refresh the connected devices list."""
        try:
            if self.demo_mode:
                return

            if not self.monitor or not self.monitor.is_available():
                return

            devices = self.monitor.get_connected_devices()

            # Clear table
            self.devices_table.setRowCount(0)

            # Add devices
            for device in devices:
                row = self.devices_table.rowCount()
                self.devices_table.insertRow(row)

                self.devices_table.setItem(row, 0, QTableWidgetItem(device.vendor_id))
                self.devices_table.setItem(row, 1, QTableWidgetItem(device.product_id))
                self.devices_table.setItem(row, 2, QTableWidgetItem(device.device_name))
                self.devices_table.setItem(row, 3, QTableWidgetItem(device.manufacturer))
                self.devices_table.setItem(row, 4, QTableWidgetItem(device.serial_number))
                self.devices_table.setItem(row, 5, QTableWidgetItem("Connected"))

        except Exception as e:
            logger.error(f"Error refreshing device list: {e}")

    def update_feeds(self):
        """Update threat intelligence feeds."""
        try:
            self.log_event("Updating threat feeds...")

            if not self.feed_integration or not self.feed_integration.is_available():
                QMessageBox.warning(
                    self,
                    "Feeds Unavailable",
                    "Threat feed integration is not available. "
                    "Please install 'requests' and 'certifi'.",
                )
                return

            sources = self.config_manager.get("feeds.sources", [])
            if not sources:
                QMessageBox.information(
                    self, "No Feeds", "No threat feeds configured."
                )
                return

            result = self.feed_integration.update_all_feeds(sources)

            if result["success"]:
                message = (
                    f"Feeds updated successfully!\n"
                    f"Updated: {result['feeds_updated']}\n"
                    f"Failed: {result['feeds_failed']}\n"
                    f"Signatures added: {result['signatures_added']}"
                )
                QMessageBox.information(self, "Feed Update", message)
                self.log_event(message.replace("\n", " - "))

                # Reload signatures in threat engine
                self.threat_engine.reload_signatures()
            else:
                QMessageBox.warning(
                    self,
                    "Feed Update Failed",
                    f"Feed update failed: {result.get('errors', [])}",
                )

        except Exception as e:
            logger.error(f"Error updating feeds: {e}")
            QMessageBox.critical(self, "Error", f"Failed to update feeds: {e}")

    def simulate_device(self):
        """Simulate device connection for demo mode."""
        from src.monitors.base_monitor import USBDevice

        # Create test device
        device = USBDevice(
            vendor_id="0x1234",
            product_id="0x5678",
            serial_number="DEMO123456",
            device_name="Demo USB Device",
            manufacturer="Demo Manufacturer",
            device_class="0x08",
        )

        self.log_event("Simulating device connection (Demo Mode)")
        self._on_device_connected_gui(device)

    def whitelist_device(self, device):
        """Add device to whitelist.

        Args:
            device: USB device to whitelist
        """
        try:
            from src.database.models import WhitelistEntry

            reply = QMessageBox.question(
                self,
                "Whitelist Device",
                f"Add device to whitelist?\n\n"
                f"Device: {device.device_name}\n"
                f"VID:PID: {device.get_vid_pid()}\n"
                f"Serial: {device.serial_number}",
                QMessageBox.Yes | QMessageBox.No,
            )

            if reply == QMessageBox.Yes:
                entry = WhitelistEntry(
                    vendor_id=device.vendor_id,
                    product_id=device.product_id,
                    serial_number=device.serial_number,
                    description=device.device_name,
                )
                self.db_manager.add_whitelist_entry(entry)
                self.log_event(f"Device whitelisted: {device.get_vid_pid()}")
                QMessageBox.information(
                    self, "Success", "Device added to whitelist"
                )

        except Exception as e:
            logger.error(f"Error whitelisting device: {e}")
            QMessageBox.critical(self, "Error", f"Failed to whitelist device: {e}")

    def log_event(self, message: str, is_threat: bool = False):
        """Log event to event log.

        Args:
            message: Event message
            is_threat: Whether this is a threat event
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        if is_threat:
            log_message = f'<span style="color: red; font-weight: bold;">{log_message}</span>'

        self.event_log.append(log_message)

        # Auto-scroll to bottom
        cursor = self.event_log.textCursor()
        cursor.movePosition(cursor.End)
        self.event_log.setTextCursor(cursor)

    def update_status(self):
        """Update status bar."""
        if self.demo_mode:
            status = "Demo Mode"
        elif self.monitoring_active:
            status = "Monitoring Active"
        else:
            status = "Monitoring Inactive"

        self.status_label.setText(f"Status: {status}")

    def update_statistics(self):
        """Update statistics display."""
        try:
            stats = self.db_manager.get_statistics()
            engine_stats = self.threat_engine.get_statistics()

            stats_text = f"""
=== Database Statistics ===
Total Events: {stats.get('total_events', 0)}
Threat Events: {stats.get('threat_events', 0)}
Threat Signatures: {stats.get('total_signatures', 0)}
Whitelisted Devices: {stats.get('whitelist_count', 0)}

=== Detection Engine ===
Signatures Enabled: {engine_stats.get('signatures_enabled', False)}
Heuristics Enabled: {engine_stats.get('heuristics_enabled', False)}
Alert Threshold: {engine_stats.get('alert_threshold', 0)}

=== Signature Statistics ===
"""
            sig_stats = engine_stats.get("signature_stats", {})
            for sig_type, count in sig_stats.items():
                stats_text += f"{sig_type}: {count}\n"

            self.stats_text.setText(stats_text)

        except Exception as e:
            logger.error(f"Error updating statistics: {e}")

    def closeEvent(self, event):
        """Handle window close event."""
        if self.config_manager.get("gui.minimize_to_tray", False):
            event.ignore()
            self.hide()
        else:
            # Stop monitoring
            if self.monitoring_active:
                self.stop_monitoring()
            event.accept()
