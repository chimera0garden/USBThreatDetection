# Contributing to USB Threat Detection

Thank you for your interest in contributing to USB Threat Detection! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/chimera0garden/USBThreatDetection/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce the bug
   - Expected vs actual behavior
   - Your environment (OS, Python version, etc.)
   - Relevant logs or screenshots

### Suggesting Features

1. Check existing issues and discussions
2. Create a new issue describing:
   - The problem your feature would solve
   - Your proposed solution
   - Any alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following our coding standards
4. Add or update tests as needed
5. Ensure all tests pass: `pytest tests/`
6. Update documentation if needed
7. Commit with clear, descriptive messages
8. Push to your fork
9. Submit a pull request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/chimera0garden/USBThreatDetection.git
cd USBThreatDetection

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run code quality checks
black src/ tests/
flake8 src/ tests/
mypy src/
```

## Coding Standards

### Python Style

- Follow PEP 8
- Use Black for formatting (line length: 100)
- Use type hints where appropriate
- Write docstrings for all public functions/classes

### Testing

- Write unit tests for new features
- Maintain or improve code coverage (target: >80%)
- Use pytest fixtures for common setup
- Mock external dependencies

### Documentation

- Update README.md for user-facing changes
- Add docstrings to new code
- Update architecture docs for significant changes
- Include code examples where helpful

### Commit Messages

Format: `type(scope): description`

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build/tooling changes

Example: `feat(monitors): add macOS USB monitoring support`

## Security

### Reporting Vulnerabilities

Please report security vulnerabilities to the maintainers privately. Do not create public issues for security problems.

### Security Considerations

- Sanitize all external inputs (threat feeds, USB device data)
- Use parameterized queries for database operations
- Validate and verify threat intelligence sources
- Don't log sensitive information
- Follow principle of least privilege

## Testing

### Running Tests

```bash
# All tests
pytest tests/

# With coverage
pytest tests/ --cov

# Specific test file
pytest tests/test_monitors.py

# Smoke test
python tests/smoke_test.py
```

### Test Structure

- Unit tests: Test individual components in isolation
- Integration tests: Test component interactions
- Platform tests: Test platform-specific functionality
- Smoke test: Quick validation without GUI/network

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release branch: `release/vX.Y.Z`
4. Run full test suite
5. Build and test packages
6. Tag release: `git tag vX.Y.Z`
7. Push tag and create GitHub release

## Questions?

Feel free to ask questions by:
- Opening a discussion on GitHub
- Commenting on relevant issues
- Reaching out to maintainers

Thank you for contributing!
