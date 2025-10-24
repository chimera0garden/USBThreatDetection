# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-24

### Added
- Initial release of USB Threat Detection system
- Real-time USB device monitoring for Windows and Linux
- Built-in signature-based threat detection
- Heuristic analysis for suspicious USB devices
- Threat intelligence feed integration (STIX 2.0, MISP)
- Cross-platform GUI application (PyQt5)
- SQLite database for event logging
- Demo Mode for testing without platform dependencies
- Automatic dependency installation
- Configuration file support (YAML)
- Whitelist management for trusted devices
- Desktop notifications for detected threats
- Comprehensive logging system
- Smoke test for quick validation
- Windows EXE build support (PyInstaller)
- Unit and integration tests
- CI/CD pipeline (GitHub Actions)
- Complete documentation

### Platform Support
- Windows 10/11 (with pywin32, wmi)
- Linux (with pyusb or pyudev)

### Security Features
- Input sanitization for threat feeds
- TLS certificate verification
- Parameterized SQL queries
- No storage of sensitive data
- Privilege escalation handling

## [Unreleased]

### Planned Features
- macOS support
- Enhanced heuristic detection rules
- PDF/HTML threat reports
- Quarantine/block actions for detected threats
- Dark mode UI theme
- Advanced whitelist with device fingerprinting
- Custom threat signature editor
- RESTful API for integration
- Docker containerization
- Multi-language support

---

[1.0.0]: https://github.com/chimera0garden/USBThreatDetection/releases/tag/v1.0.0
