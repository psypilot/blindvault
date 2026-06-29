# Builds the Windows artifacts: BlindVault.exe (GUI), bv.exe (CLI), and
# BlindVault-Setup.exe (installer).
#
# Requires: Python 3.9+, and Inno Setup 6 (iscc) for the installer step.
# Usage:    powershell -ExecutionPolicy Bypass -File installer\build-windows.ps1 -Version 0.9.0
param([string]$Version = "0.0.0")
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)   # repo root

python -m pip install --quiet pyinstaller cryptography pywin32

# GUI app (windowed)
python -m PyInstaller --onefile --windowed --name BlindVault `
  --icon assets/blindvault.ico --add-data "assets/blindvault.ico;." --noconfirm app.py

# CLI (console) — bundle the lazily-imported broker/gui submodules so all
# subcommands (serve --pipe, proxy, gui, ...) work from the standalone exe.
python -m PyInstaller --onefile --console --name bv `
  --icon assets/blindvault.ico --add-data "assets/blindvault.ico;." `
  --hidden-import blindvault.broker.server --hidden-import blindvault.broker.winpipe `
  --hidden-import blindvault.broker.pgproxy --hidden-import blindvault.broker.hardening `
  --hidden-import blindvault.broker.peercred --hidden-import blindvault.gui `
  --noconfirm cli_entry.py

# Installer (needs Inno Setup 6)
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { $iscc = "iscc" }   # fall back to PATH
& $iscc "/DMyAppVersion=$Version" installer\blindvault.iss

Write-Output "Done -> dist\BlindVault.exe, dist\bv.exe, dist\BlindVault-Setup.exe"
