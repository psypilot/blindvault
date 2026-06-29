"""Console entry point bundled into bv.exe by PyInstaller.

The CLI lazily imports the broker/gui submodules, which PyInstaller's static
analysis won't follow — the build passes them as --hidden-import (see
installer/build-windows.ps1 and .github/workflows/release.yml).
"""

from blindvault.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
