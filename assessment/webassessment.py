import sys
from PyQt5.QtWidgets import QApplication
from assessment.gui.main import Main


def start_app():
    app = QApplication(sys.argv)
    win = Main()
    win.show()
    sys.exit(app.exec())