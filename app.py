"""Double-clickable entry point for the desktop app.

This is what PyInstaller bundles into BlindVault.exe. It simply launches the GUI
defined in the package.
"""

from blindvault.gui import main

if __name__ == "__main__":
    raise SystemExit(main())
