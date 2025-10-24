#!/bin/bash
# Build script for Linux USB Threat Detection

echo "============================================================"
echo "USB Threat Detection - Linux Build Script"
echo "============================================================"
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    echo "Please install Python 3.8+"
    exit 1
fi

echo "Python version:"
python3 --version
echo

# Check if PyInstaller is available
if ! python3 -c "import PyInstaller" &> /dev/null; then
    echo "Installing PyInstaller..."
    pip3 install --user pyinstaller
fi

echo
echo "Building executable..."
echo

# Change to build directory
cd "$(dirname "$0")"

# Run PyInstaller with spec file
python3 -m PyInstaller USBThreatDetection.spec

if [ $? -ne 0 ]; then
    echo
    echo "ERROR: Build failed!"
    exit 1
fi

echo
echo "============================================================"
echo "Build completed successfully!"
echo "============================================================"
echo
echo "Executable location: dist/USBThreatDetection/USBThreatDetection"
echo
echo "NOTE: You may need root privileges for USB monitoring"
echo

# Make executable
chmod +x dist/USBThreatDetection/USBThreatDetection

echo "Done!"
