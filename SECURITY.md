# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: Send details to the project maintainers (check repository for contact)
2. **Include**:
   - Type of vulnerability
   - Full paths of affected source files
   - Location of affected code (tag/branch/commit)
   - Step-by-step instructions to reproduce
   - Proof-of-concept or exploit code (if possible)
   - Impact assessment
   - Suggested fix (if available)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Regular Updates**: Every 7-14 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 7-30 days
  - Medium: 30-90 days
  - Low: Best effort

### Disclosure Policy

- We follow coordinated disclosure
- Security advisories published after fixes are released
- Credit given to reporters (unless anonymity requested)

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest version
2. **Verify Downloads**: Check file hashes and signatures
3. **Run with Least Privilege**: Only elevate when necessary
4. **Review Logs**: Monitor for suspicious activity
5. **Secure Configuration**: Use strong passwords, enable encryption
6. **Trusted Feeds Only**: Verify threat intelligence sources

### For Developers

1. **Input Validation**: Sanitize all external inputs
2. **SQL Injection**: Use parameterized queries only
3. **Dependencies**: Keep dependencies updated, scan regularly
4. **Secrets**: Never commit credentials or API keys
5. **Code Review**: All security-critical code requires review
6. **Testing**: Include security test cases
7. **Logging**: Don't log sensitive data (PII, credentials)

## Known Security Considerations

### Admin/Root Privileges

USB monitoring requires elevated privileges on most platforms:
- **Windows**: Administrator rights for WMI queries
- **Linux**: Root or udev rules for USB access

**Mitigation**: We minimize privilege scope and duration. Consider:
- Using udev rules on Linux instead of root
- Running only monitoring components with elevation

### Threat Feed Trust

Threat intelligence feeds are external data sources:
- **Risk**: Malicious or compromised feeds
- **Mitigation**:
  - Verify feed sources (TLS, signatures)
  - Validate and sanitize all feed data
  - Implement rate limiting
  - Allow feed disabling

### Network Communication

The application makes network requests for threat feeds:
- **Risk**: Man-in-the-middle attacks, data leakage
- **Mitigation**:
  - HTTPS only with certificate verification
  - No sensitive data transmitted
  - Offline mode available

### Database Security

SQLite database stores event logs:
- **Risk**: Unauthorized access to logs
- **Mitigation**:
  - File permissions restrict access
  - No credentials stored
  - Optional encryption (future feature)

### Third-Party Dependencies

We rely on external libraries:
- **Risk**: Vulnerabilities in dependencies
- **Mitigation**:
  - Regular dependency updates
  - Automated security scanning (pip-audit)
  - Minimal dependency footprint

## Security Features

- Input sanitization for all external data
- Parameterized SQL queries (no string concatenation)
- TLS certificate verification for network requests
- Principle of least privilege
- Comprehensive logging (without sensitive data)
- Graceful degradation (Demo Mode when privileges unavailable)

## Security Testing

We perform:
- Static analysis (mypy, pylint, flake8)
- Dependency scanning (pip-audit)
- Manual security review for critical components
- Penetration testing (periodic)

## Compliance

This tool is designed for defensive security purposes only:
- Detects malicious USB devices
- Monitors for security threats
- Complies with responsible disclosure practices

## Questions?

For security-related questions (non-vulnerabilities), please open a GitHub issue with the `security` label.

Thank you for helping keep USB Threat Detection secure!
