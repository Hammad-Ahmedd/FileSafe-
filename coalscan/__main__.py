"""Application entry point for `python -m coalscan`."""

from __future__ import annotations

import multiprocessing
import sys

from PySide6.QtWidgets import QApplication

from coalscan.ui.main_window import MainWindow


def main() -> int:
    """Launch the CoalScan PySide6 Windows desktop application."""
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    app.setApplicationName("FileSafe - Assembly-Assisted Malware Analysis (CSC-203)")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
