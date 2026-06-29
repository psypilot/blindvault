# Builds dist/BlindVault.exe — a standalone desktop app (no Python needed to run it).
# Usage:  powershell -ExecutionPolicy Bypass -File build_exe.ps1
python -m pip install --quiet pyinstaller cryptography
python -m PyInstaller --onefile --windowed --name BlindVault `
  --icon assets/blindvault.ico `
  --add-data "assets/blindvault.ico;." `
  --clean --noconfirm app.py
Write-Output "Done -> dist\BlindVault.exe"
