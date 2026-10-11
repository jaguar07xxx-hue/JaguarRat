# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from jaguar.ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Jaguar")
    ventana = MainWindow()
    ventana.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()