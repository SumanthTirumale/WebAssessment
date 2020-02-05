import json
import datetime

from pathlib import Path

from PyQt5.QtWidgets import QDialog, QApplication, QVBoxLayout, QGridLayout, QLineEdit, QPushButton, QLabel, QFileDialog, QMessageBox
from PyQt5.QtGui import QIcon
from PyQt5.Qt import Qt
from PyQt5.QtCore import pyqtSignal

from assessment.database import WebAssessmentDb
from assessment.reports import Reports
from assessment.vulnerabilities.active_header_audit import ActiveHeaderAudit


class ClickableLineEdit(QLineEdit):
    clicked = pyqtSignal()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        else:
            super().mousePressEvent(event)


class Report(QDialog):

    def __init__(self):
        super(Report, self).__init__()
        self.setWindowTitle("Web Assessment")
        self.image_path = str(Path(__file__).absolute().parent.parent / "static")
        self.setWindowIcon(QIcon(str(Path(self.image_path)/"logo.ico")))
        self.setFixedSize(400, 150)

        # init widgets
        self.txt_db_path = ClickableLineEdit()
        self.txt_as_path = ClickableLineEdit()

        self.btn_generate = QPushButton("Generate")
        self.btn_clear_all = QPushButton("Clear All")

        self.center()
        self.init_ui()
        self.init_signals()

    def center(self):
        """Method to center the QMainWindow"""
        frame_gm = self.frameGeometry()
        screen = QApplication.desktop().screenNumber(QApplication.desktop().cursor().pos())
        center_point = QApplication.desktop().screenGeometry(screen).center()
        frame_gm.moveCenter(center_point)
        self.move(frame_gm.topLeft())

    def init_ui(self):
        vertical_box = QVBoxLayout()
        grid_layout = QGridLayout()

        lbl_db_path = QLabel("Database Path")
        lbl_as_path = QLabel("Assessment File Path")

        grid_layout.addWidget(lbl_db_path, 0, 0)
        grid_layout.addWidget(self.txt_db_path, 0, 1, 1, -1)

        grid_layout.addWidget(lbl_as_path, 1, 0)
        grid_layout.addWidget(self.txt_as_path, 1, 1, 1, -1)

        grid_layout.addWidget(self.btn_generate, 2, 1)
        grid_layout.addWidget(self.btn_clear_all, 2, 2)

        vertical_box.addLayout(grid_layout)
        self.setLayout(vertical_box)
        self.setWindowModality(Qt.ApplicationModal)
        self.show()

    def init_signals(self):
        self.txt_db_path.clicked.connect(self.get_db_file)
        self.txt_as_path.clicked.connect(self.get_as_file)
        self.btn_generate.clicked.connect(self.validate_fields)
        self.btn_clear_all.clicked.connect(self.clear_all)

    def get_db_file(self):
        """signal to get db file"""
        _filter = "file (*.db)"

        db_file_path = QFileDialog.getOpenFileName(self, "Open a file", '', filter=_filter)[0]

        if len(db_file_path) > 0:
            self.txt_db_path.clear()
            self.txt_db_path.setText(db_file_path)
        else:
            self.txt_db_path.clear()

    def get_as_file(self):
        """signal to get db file"""
        _filter = "file (*.as)"

        as_file_path = QFileDialog.getOpenFileName(self, "Open a file", '', filter=_filter)[0]

        if len(as_file_path) > 0:
            self.txt_as_path.clear()
            self.txt_as_path.setText(as_file_path)
        else:
            self.txt_as_path.clear()

    def clear_all(self):
        """signal to clear all widgets"""
        self.txt_db_path.clear()
        self.txt_as_path.clear()

    def validate_fields(self):
        _empty_data = ["", None]

        if self.txt_db_path.text() not in _empty_data:

            if Path(self.txt_db_path.text()).is_file():

                if self.txt_as_path.text() not in _empty_data:

                    if Path(self.txt_as_path.text()).is_file():
                        self.generate_report()

                    else:
                        QMessageBox.information(self, "Warning", f"Selected \".as\" file doesnt exists!")
                else:
                    QMessageBox.information(self, "Warning","Please selecet Web Assessment generated \".as\" file")
            else:
                QMessageBox.information(self, "Warning", f"Selected \".db\" file doesnt exists!")
        else:
            QMessageBox.information(self, "Warning", "Please select Web Assessment generated \".db\" file")

    def generate_report(self):
        # create instance of WebAssessment db
        assessment_db = WebAssessmentDb(self.txt_db_path.text(), True)

        with open(self.txt_as_path.text(), 'r') as f:
            config_dict = json.load(f)

        # record execution start date
        start_date_time = datetime.datetime.now()

        # record end date time
        end_date_time = datetime.datetime.now()

        if 'secure_header_file_path' in config_dict.keys():
            active_header_audit = ActiveHeaderAudit(self.config['secure_header_file_path'])
        else:
            active_header_audit = False

        # if secure header check is checked add it to the list
        config_dict['security_risks'].append('secureheadercheck')

        reports = Reports(
            database=assessment_db, vulnerability_type=config_dict['security_risks'],
            config_dict=config_dict, start_date_time=start_date_time, end_date_time=end_date_time
        )

        return_data = reports.get_reports()

        # close database connection
        assessment_db.close_connection()

        if len(return_data) > 0:
            QMessageBox.information(self, "information", f"Reports generated in {return_data}")
        else:
            QMessageBox.information(self, "information", "Reports has been not generated")




