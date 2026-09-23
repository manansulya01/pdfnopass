"""Allow `python -m pdf_recovery` execution."""
import sys

try:
    # Normal package execution (`python -m pdf_recovery`).
    from .cli import main
except ImportError:  # pragma: no cover - frozen (PyInstaller) entry point
    # When bundled, the entry script runs without package context, so the
    # relative import above fails; fall back to the absolute import (the
    # package itself is still collected by the build).
    from pdf_recovery.cli import main

if __name__ == "__main__":
    import multiprocessing

    # Required for frozen executables (PyInstaller) on macOS/Windows: child
    # worker processes are spawned by re-launching the executable with
    # internal multiprocessing flags; freeze_support() intercepts those so
    # they never reach the CLI parser. No-op when running as plain Python.
    multiprocessing.freeze_support()
    sys.exit(main())
