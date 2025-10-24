@echo off
REM Build script for Windows USB Threat Detection EXE

echo ============================================================
echo USB Threat Detection - Windows Build Script
echo ============================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH
    echo Please install Python 3.8+ and add it to PATH
    pause
    exit /b 1
)

echo Checking dependencies...
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo.
echo Building executable...
echo.

REM Change to build directory
cd /d "%~dp0"

REM Run PyInstaller with spec file
pyinstaller USBThreatDetection.spec

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ============================================================
echo Build completed successfully!
echo ============================================================
echo.
echo Executable location: dist\USBThreatDetection\USBThreatDetection.exe
echo.
echo NOTE: Remember to run as Administrator for full USB monitoring
echo.

pause
