@echo off
set PORT=5150
echo Adding Windows Firewall rule for IQRA GROUP OF LABORATORY LIMS TCP port %PORT%...
netsh advfirewall firewall add rule name="IQRA GROUP OF LABORATORY LIMS %PORT%" dir=in action=allow protocol=TCP localport=%PORT%
if errorlevel 1 (
 echo.
 echo Please right-click this file and choose "Run as administrator".
) else (
 echo Firewall rule added successfully for TCP %PORT%.
)
pause
