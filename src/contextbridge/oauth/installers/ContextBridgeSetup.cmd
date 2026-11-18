@echo off
rem ContextBridge setup for Windows: installs the ContextBridge agent on this computer.
rem Administrator approval is required to install; Windows asks for it (UAC) when this starts.
rem The device is added by browser approval: this window shows a code to enter at __CONTEXTBRIDGE_SERVER__/activate
net session >nul 2>&1
if errorlevel 1 (
  set "CB_SELF=%~f0"
  powershell.exe -NoProfile -Command "Start-Process -Verb RunAs -FilePath $env:CB_SELF"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm -UseBasicParsing -ErrorAction Stop '__CONTEXTBRIDGE_SERVER__/install/remote-windows.ps1' | iex"
echo.
pause
