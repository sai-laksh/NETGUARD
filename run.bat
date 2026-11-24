@echo off
title NETGUARD - Smart Campus Network Monitoring System
echo ======================================================================
echo  NETGUARD - SMART CAMPUS NETWORK MONITORING AND SECURITY SYSTEM
echo  Theme: Dark Emerald Green SOC Dashboard
echo  Capstone Project | Computer Networks (CN)
echo ======================================================================
echo.

:: Check for python in PATH
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Found Python in PATH. Starting Flask Server...
    python app.py
    goto end
)

:: Check for py launcher
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Found Python Launcher (py). Starting Flask Server...
    py app.py
    goto end
)

:: Check common AppData Python path
if exist "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" (
    echo [INFO] Found Python 3.9 in AppData. Starting Flask Server...
    "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" app.py
    goto end
)

:: Fallback: Open index.html directly in default browser
echo [INFO] Python not detected in standard paths.
echo [INFO] Launching NETGUARD Dashboard directly in your default browser...
start index.html

:end
pause
