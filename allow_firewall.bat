@echo off
title Allow Cyber Triage Port 5000 in Windows Firewall
echo ======================================================================
echo   CONFIGURING WINDOWS FIREWALL FOR PORT 5000 (CYBER TRIAGE TOOL)
echo ======================================================================
echo.
echo Adding inbound firewall rule for Port 5000...
netsh advfirewall firewall add rule name="Cyber Triage Platform Port 5000" dir=in action=allow protocol=TCP localport=5000
echo.
if %errorlevel% equ 0 (
    echo [SUCCESS] Port 5000 is now open for other devices on your Wi-Fi/LAN!
) else (
    echo [NOTE] If this failed, please right-click this file and select 'Run as administrator'.
)
echo.
pause
