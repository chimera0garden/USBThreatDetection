"""Configuration management for USB Threat Detection."""

import os
import logging
from typing import Dict, Any, Optional
import yaml

logger = logging.getLogger(__name__)


class ConfigManager:
    """Configuration manager for loading and accessing configuration."""

    DEFAULT_CONFIG = {
        "database": {"path": "usb_threat_detection.db", "wal_mode": True},
        "logging": {
            "file": "usb_detection.log",
            "level": "INFO",
            "max_bytes": 10485760,
            "backup_count": 5,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
        "monitoring": {
            "scan_interval": 5,
            "enable_hotplug": True,
            "scan_files": True,
            "max_scan_depth": 3,
            "max_file_size": 104857600,
        },
        "detection": {
            "enable_signatures": True,
            "enable_heuristics": True,
            "alert_threshold": 50,
            "enable_notifications": True,
        },
        "feeds": {
            "enable": True,
            "update_interval": 3600,
            "cache_ttl": 86400,
            "timeout": 30,
            "max_feed_size": 10485760,
            "sources": [],
        },
        "whitelist": {"enable": True, "file": "whitelist.yaml", "devices": []},
        "gui": {
            "window_width": 1024,
            "window_height": 768,
            "theme": "light",
            "show_tray_icon": True,
            "minimize_to_tray": False,
            "refresh_interval": 1000,
        },
        "security": {
            "verify_ssl": True,
            "max_redirects": 3,
            "user_agent": "USBThreatDetection/1.0",
        },
        "performance": {"max_workers": 4, "async_mode": True, "db_pool_size": 5},
    }

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.

        Args:
            config_path: Path to configuration file (optional)
        """
        self.config_path = config_path
        self.config = self.DEFAULT_CONFIG.copy()

        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
        else:
            # Try default locations
            default_paths = [
                "config/default_config.yaml",
                "/etc/usb-threat-detection/config.yaml",
                os.path.expanduser("~/.config/usb-threat-detection/config.yaml"),
            ]
            for path in default_paths:
                if os.path.exists(path):
                    self.load_config(path)
                    break

    def load_config(self, config_path: str) -> bool:
        """Load configuration from file.

        Args:
            config_path: Path to YAML configuration file

        Returns:
            True if successful
        """
        try:
            with open(config_path, "r") as f:
                user_config = yaml.safe_load(f)

            if user_config:
                self._merge_config(self.config, user_config)
                logger.info(f"Configuration loaded from {config_path}")
                return True
            else:
                logger.warning(f"Empty configuration file: {config_path}")
                return False

        except Exception as e:
            logger.error(f"Error loading configuration from {config_path}: {e}")
            return False

    def _merge_config(self, base: Dict, update: Dict):
        """Recursively merge configuration dictionaries.

        Args:
            base: Base configuration dictionary (modified in place)
            update: Update configuration dictionary
        """
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value by key path.

        Args:
            key_path: Dot-separated key path (e.g., "database.path")
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key_path.split(".")
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path: str, value: Any):
        """Set configuration value by key path.

        Args:
            key_path: Dot-separated key path (e.g., "database.path")
            value: Value to set
        """
        keys = key_path.split(".")
        config = self.config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section.

        Args:
            section: Section name (e.g., "database")

        Returns:
            Configuration section dictionary
        """
        return self.config.get(section, {})

    def save_config(self, config_path: Optional[str] = None) -> bool:
        """Save configuration to file.

        Args:
            config_path: Path to save to (uses loaded path if None)

        Returns:
            True if successful
        """
        save_path = config_path or self.config_path

        if not save_path:
            logger.error("No config path specified for saving")
            return False

        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            with open(save_path, "w") as f:
                yaml.safe_dump(self.config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Configuration saved to {save_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving configuration to {save_path}: {e}")
            return False

    def setup_logging(self):
        """Setup logging based on configuration."""
        log_config = self.get_section("logging")

        # Create formatter
        formatter = logging.Formatter(log_config.get("format"))

        # Setup file handler
        try:
            from logging.handlers import RotatingFileHandler

            file_handler = RotatingFileHandler(
                log_config.get("file", "usb_detection.log"),
                maxBytes=log_config.get("max_bytes", 10485760),
                backupCount=log_config.get("backup_count", 5),
            )
            file_handler.setFormatter(formatter)

            # Setup root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(log_config.get("level", "INFO"))
            root_logger.addHandler(file_handler)

            # Also add console handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

            logger.info("Logging configured successfully")

        except Exception as e:
            print(f"Error setting up logging: {e}")

    def validate(self) -> bool:
        """Validate configuration.

        Returns:
            True if configuration is valid
        """
        errors = []

        # Validate required sections
        required_sections = ["database", "logging", "monitoring", "detection"]
        for section in required_sections:
            if section not in self.config:
                errors.append(f"Missing required section: {section}")

        # Validate database path
        db_path = self.get("database.path")
        if not db_path:
            errors.append("Database path not configured")

        # Validate logging level
        log_level = self.get("logging.level")
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if log_level not in valid_levels:
            errors.append(f"Invalid logging level: {log_level}")

        # Validate threshold
        threshold = self.get("detection.alert_threshold")
        if not isinstance(threshold, int) or threshold < 0 or threshold > 100:
            errors.append(f"Invalid alert threshold: {threshold} (must be 0-100)")

        if errors:
            for error in errors:
                logger.error(f"Configuration validation error: {error}")
            return False

        logger.info("Configuration validation passed")
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary.

        Returns:
            Configuration dictionary
        """
        return self.config.copy()
