@echo off
cd /d "%~dp0"
set LIMS_PORT=5150
set LIMS_HOST=0.0.0.0
set "TITLE=IQRA GROUP OF LAB LIMS"
title %TITLE%
echo =====================================================
echo       IQRA GROUP OF LAB - LIMS SERVER
echo =====================================================
echo Port: %LIMS_PORT%
echo.
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /R /C:"IPv4 Address" /C:"IPv4"') do echo LAN IP: %%A
echo.
echo Open on this PC: http://localhost:%LIMS_PORT%
echo On other PCs use: http://SERVER-PC-IP:%LIMS_PORT%
echo.
echo Starting server...
node server.js
if errorlevel 1 (
 echo.
 echo Server could not start. Check the error above.
 pause
)
