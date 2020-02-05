import json
import datetime

from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon, QDoubleValidator, QIntValidator
from PyQt5.QtCore import pyqtSignal
from PyQt5.Qt import Qt
from pathlib import Path

from assessment.helpers import ping, create_folder, get_requests
from assessment.gui.report import Report
from assessment.requests import Requests
from assessment.vulnerabilities.xss import Xss
from assessment.vulnerabilities.bufferoverflow import BufferOverflow
from assessment.vulnerabilities.active_header_audit import ActiveHeaderAudit
from assessment.vulnerabilities.csrf import Csrf
from assessment.vulnerabilities.directory_traversal import DirectoryTraversal
from assessment.vulnerabilities.authorization_bypass import AuthorizationByPass
from assessment.database import WebAssessmentDb
from assessment.reports import Reports


class ClickableLineEdit(QLineEdit):
    clicked = pyqtSignal()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        else:
            super().mousePressEvent(event)


class Main(QMainWindow):

    def __init__(self):
        super(Main, self).__init__()

        self.setWindowTitle("Web Assessment")
        self.image_path = str(Path(__file__).absolute().parent.parent / "static")
        self.setWindowIcon(QIcon(str(Path(self.image_path) / "logo.ico")))
        self.setFixedSize(self.size())

        # initialize menu
        menu_bar = self.menuBar()
        self.menu_file = menu_bar.addMenu("File")
        self.menu_generate_report = QAction("Generate Report")

        self.config = {}

        # layout
        self.grid_layout = QGridLayout()

        # path
        self.data_store_path = create_folder()

        # initialize widgets
        self.lbl_secure_header_file_path = QLabel("Secure header File Path")
        self.lbl_secure_header_file_path.setVisible(False)
        self.txt_host_address = QLineEdit()
        self.txt_host_name = QLineEdit()
        self.txt_host_release_version = QLineEdit()
        self.txt_response_time = QLineEdit()
        self.txt_response_time.setValidator(QDoubleValidator(0.00, 99.99, 4))
        self.txt_num_of_retries = QLineEdit()
        self.txt_num_of_retries.setValidator(QIntValidator())
        self.txt_request_file_path = ClickableLineEdit()
        self.txt_secure_header_file_path = ClickableLineEdit()
        self.txt_secure_header_file_path.setVisible(False)
        self.txt_url_exclusion = QLineEdit()
        self.txt_header_exclusion = QLineEdit()
        self.txt_header_exclusion.setText("Host")

        self.combo_protocol_type = QComboBox()
        self.combo_protocol_type.addItems(("https", "http", ))
        self.combo_printer_type = QComboBox()
        self.combo_printer_type.addItems(("VEP", "SOL", "Sirius Classic", "Apollo", "Phoenix", ))

        self.check_box_sec_risk_xss = QCheckBox("XSS")
        self.check_box_sec_risk_buffer_overflow = QCheckBox("Buffer Overflow")
        self.check_box_sec_risk_auth_bypass = QCheckBox("Authorization Bypass")
        self.check_box_sec_risk_csrf = QCheckBox("CSRF")
        self.check_box_sec_risk_dir_traversal = QCheckBox("Directory Traversal")
        self.check_box_assessment_head = QCheckBox("Head")
        self.check_box_assessment_body = QCheckBox("Body")
        self.check_box_assessment_url = QCheckBox("Url")

        self.radio_btn_secure_header_true = QRadioButton("True")
        self.radio_btn_secure_header_false = QRadioButton("False")
        self.radio_btn_secure_header_false.setChecked(True)

        self.btn_start = QPushButton("Start")
        self.btn_clear = QPushButton("Clear")

        self.center()
        self.init_menu()
        self.init_ui()
        self.init_signals()

    def center(self):
        """Method to center the QMainWindow"""
        frame_gm = self.frameGeometry()
        screen = QApplication.desktop().screenNumber(QApplication.desktop().cursor().pos())
        center_point = QApplication.desktop().screenGeometry(screen).center()
        frame_gm.moveCenter(center_point)
        self.move(frame_gm.topLeft())

    def init_menu(self):
        self.menu_file.addAction(self.menu_generate_report)

    def init_signals(self):
        """Method to initialise the signals of the widgets"""
        self.txt_request_file_path.clicked.connect(self.get_request_file)
        self.txt_secure_header_file_path.clicked.connect(self.get_secured_header_file)
        self.btn_clear.clicked.connect(self.reset_widgets)
        self.btn_start.clicked.connect(self.start)
        self.radio_btn_secure_header_true.toggled.connect(self.check_secure_header_value)
        self.menu_generate_report.triggered.connect(self.generate_report)

    def init_ui(self):
        vertical_box = QVBoxLayout()
        # grid_layout.setContentsMargins(0, 20, 0, 0)

        lbl_host_address = QLabel("Host Address")
        lbl_host_name = QLabel("Host Name")
        lbl_release_version = QLabel("Release Version")
        lbl_protocol_type = QLabel("Protocol Type")
        lbl_printer_type = QLabel("Printer Type")
        lbl_response_time = QLabel("Response Time")
        lbl_num_of_retries = QLabel("Number Of Retries")
        lbl_request_file_path = QLabel("Requests File Path")
        lbl_security_risk = QLabel("Security Risks")

        lbl_assessment_type = QLabel("Assessment Type")
        lbl_header_exclusion = QLabel("Header Exclusion")
        lbl_url_exclusion = QLabel("Url Exclusion")
        lbl_secure_header = QLabel("Secure Header Check")

        self.grid_layout.addWidget(lbl_host_address, 0, 0)
        self.grid_layout.addWidget(self.txt_host_address, 0, 1, 1, -1)

        self.grid_layout.addWidget(lbl_host_name, 1, 0)
        self.grid_layout.addWidget(self.txt_host_name, 1, 1, 1, -1)

        self.grid_layout.addWidget(lbl_release_version, 2, 0)
        self.grid_layout.addWidget(self.txt_host_release_version, 2, 1, 1, -1)

        self.grid_layout.addWidget(lbl_protocol_type, 3, 0)
        self.grid_layout.addWidget(self.combo_protocol_type, 3, 1, 1, -1)

        self.grid_layout.addWidget(lbl_printer_type, 4, 0)
        self.grid_layout.addWidget(self.combo_printer_type, 4, 1, 1, -1)

        self.grid_layout.addWidget(lbl_response_time, 5, 0)
        self.grid_layout.addWidget(self.txt_response_time, 5, 1, 1, -1)

        self.grid_layout.addWidget(lbl_num_of_retries, 6, 0)
        self.grid_layout.addWidget(self.txt_num_of_retries, 6, 1, 1, -1)

        self.grid_layout.addWidget(lbl_request_file_path, 7, 0)
        self.grid_layout.addWidget(self.txt_request_file_path, 7, 1, 1, -1)

        self.grid_layout.addWidget(lbl_security_risk, 8, 0)
        self.grid_layout.addWidget(self.check_box_sec_risk_buffer_overflow, 8, 1)
        self.grid_layout.addWidget(self.check_box_sec_risk_dir_traversal, 8, 2)
        self.grid_layout.addWidget(self.check_box_sec_risk_auth_bypass, 8, 3)
        self.grid_layout.addWidget(self.check_box_sec_risk_xss, 9, 1)
        self.grid_layout.addWidget(self.check_box_sec_risk_csrf, 9, 2)

        self.grid_layout.addWidget(lbl_header_exclusion, 10, 0)
        self.grid_layout.addWidget(self.txt_header_exclusion, 10, 1, 1, -1)

        self.grid_layout.addWidget(lbl_url_exclusion, 11, 0)
        self.grid_layout.addWidget(self.txt_url_exclusion, 11, 1, 1, -1)

        self.grid_layout.addWidget(lbl_assessment_type, 12, 0)
        self.grid_layout.addWidget(self.check_box_assessment_url, 12, 1)
        self.grid_layout.addWidget(self.check_box_assessment_head, 12, 2)
        self.grid_layout.addWidget(self.check_box_assessment_body, 12, 3)

        self.grid_layout.addWidget(lbl_secure_header, 13, 0)
        self.grid_layout.addWidget(self.radio_btn_secure_header_true, 13, 1)
        self.grid_layout.addWidget(self.radio_btn_secure_header_false, 13, 2)

        self.grid_layout.addWidget(self.lbl_secure_header_file_path, 14, 0)
        self.grid_layout.addWidget(self.txt_secure_header_file_path, 14, 1, 1, -1)

        self.grid_layout.addWidget(self.btn_start, 15, 1)
        self.grid_layout.addWidget(self.btn_clear, 15, 2)

        vertical_box.addLayout(self.grid_layout)
        self.setCentralWidget(QWidget(self))
        self.centralWidget().setLayout(vertical_box)

    def get_request_file(self):
        """signal to get request file"""
        _filter = "file (*.json)"

        request_file_path = QFileDialog.getOpenFileName(self, "Open a file", '', filter=_filter)[0]

        if len(request_file_path) > 0:
            self.txt_request_file_path.clear()
            self.txt_request_file_path.setText(request_file_path)
        else:
            self.txt_request_file_path.clear()

    def get_secured_header_file(self):
        """signal to get request file"""
        _filter = "file (*.json)"

        request_file_path = QFileDialog.getOpenFileName(self, "Open a file", '', filter=_filter)[0]

        if len(request_file_path) > 0:
            self.txt_secure_header_file_path.clear()
            self.txt_secure_header_file_path.setText(request_file_path)
        else:
            self.txt_secure_header_file_path.clear()

    def reset_widgets(self):
        """signal to reset all widgets"""
        self.clear()

        self.radio_btn_secure_header_false.setChecked(True)
        self.txt_header_exclusion.setText("Host")

    def start(self):
        """signal to verify the input values and create create a dict"""

        _empty_list = ["", None]

        if self.txt_host_address.text() not in _empty_list:

            address = self.txt_host_address.text()
            if ping(address):

                if self.txt_host_name.text() not in _empty_list:

                    if self.txt_host_release_version.text() not in _empty_list:

                        if self.txt_response_time.text() not in _empty_list:

                            if self.txt_num_of_retries.text() not in _empty_list:

                                if self.txt_request_file_path.text() not in _empty_list:

                                    if Path(self.txt_request_file_path.text()).is_file():

                                        _bf = self.check_box_sec_risk_buffer_overflow.isChecked()
                                        _xss = self.check_box_sec_risk_xss.isChecked()
                                        _dir_traversal = self.check_box_sec_risk_dir_traversal.isChecked()
                                        _auth_bypass = self.check_box_sec_risk_auth_bypass.isChecked()
                                        _csrf = self.check_box_sec_risk_csrf.isChecked()

                                        if not _bf and not _xss and not _dir_traversal and not _auth_bypass and not _csrf:

                                            QMessageBox.information(self, "Warning", "Please select a security risk!")

                                        else:
                                            if self.txt_secure_header_file_path.text() not in _empty_list:

                                                if not Path(self.txt_secure_header_file_path.text()).is_file():
                                                    QMessageBox.information(self, "Warning",
                                                                            "Secure Header file doesn't exists!")

                                            _url = self.check_box_assessment_url.isChecked()
                                            _head = self.check_box_assessment_head.isChecked()
                                            _body = self.check_box_assessment_body.isChecked()

                                            if not _url and not _head and not _body:
                                                QMessageBox.information(self, "Warning",
                                                                        "Please select a assessment type!")
                                            else:
                                                self.get_values_from_widgets()
                                    else:
                                        QMessageBox.information(self, "Warning", "Request file doesn't exists!")
                                else:
                                    QMessageBox.information(self, "Warning", "Please enter request file")
                            else:
                                QMessageBox.information(self, "Warning", "Please enter max retries")
                        else:
                            QMessageBox.information(self, "Warning", "Please enter response time")
                    else:
                        QMessageBox.information(self, "Warning", "Please enter release version")
                else:
                    QMessageBox.information(self, "Warning", "Please enter host name")
            else:
                QMessageBox.information(self, "Warning", "Host address is unreachable!")

        else:
            QMessageBox.information(self, "Warning", "Please enter host address")

    def check_secure_header_value(self):
        """Signal to set secure header value"""

        if self.radio_btn_secure_header_true.isChecked():
            self.lbl_secure_header_file_path.setVisible(True)
            self.txt_secure_header_file_path.setVisible(True)
        else:
            self.lbl_secure_header_file_path.setVisible(False)
            self.txt_secure_header_file_path.setVisible(False)

    def get_values_from_widgets(self):
        """method to get values from widgets and save it to 'self.config' dictionary"""

        self.config['ip_address'] = str(self.txt_host_address.text())
        self.config['printer_name'] = str(self.txt_host_name.text()).lower()
        self.config['release_version'] = str(self.txt_host_release_version.text())
        self.config['protocol_type'] = str(self.combo_protocol_type.currentText()).lower()
        self.config['printer_type'] = str(self.combo_printer_type.currentText()).lower()
        self.config['response_time'] = str(self.txt_response_time.text())
        self.config['number_of_retries'] = str(self.txt_num_of_retries.text())
        self.config['request_file_path'] = str(self.txt_request_file_path.text())

        risk_type = {
            'xss': self.check_box_sec_risk_xss.isChecked(),
            'bufferoverflow': self.check_box_sec_risk_buffer_overflow.isChecked(),
            'csrf': self.check_box_sec_risk_csrf.isChecked(),
            'directorytraversal': self.check_box_sec_risk_dir_traversal.isChecked(),
            'authorizationbypass': self.check_box_sec_risk_auth_bypass.isChecked(),
        }

        _tmp_list = []
        for risk, value in risk_type.items():
            if value:
                _tmp_list.append(risk)

        self.config['security_risks'] = _tmp_list

        assessment_type = {
            'url': self.check_box_assessment_url.isChecked(),
            'body': self.check_box_assessment_body.isChecked(),
            'head': self.check_box_assessment_head.isChecked(),
        }

        _tmp_list = []
        for assessment, value in assessment_type.items():
            if value:
                _tmp_list.append(assessment)

        self.config['assessment_type'] = _tmp_list

        if self.radio_btn_secure_header_true.isChecked():

            if len(self.txt_secure_header_file_path.text()) > 0:
                self.config['secure_header_file_path'] = self.txt_secure_header_file_path.text()

        if len(self.txt_header_exclusion.text()) > 0:
            _header_exclusion = self.txt_header_exclusion.text().split(",")
            self.config['header_exclusion'] = _header_exclusion

        if len(self.txt_url_exclusion.text()) > 0:
            _url_exclusion = self.txt_url_exclusion.text().split(",")
            self.config['url_exclusion'] = _url_exclusion

        self.hide()

        json_file_name = Path(self.data_store_path)/f"{self.txt_host_address.text()}.as"

        with open(json_file_name, "w") as f:
            json.dump(self.config, f)

        self.start_assessment()

    def clear(self):
        """method to clear all the widgets"""
        self.txt_header_exclusion.clear()
        self.txt_url_exclusion.clear()
        self.txt_host_address.clear()
        self.txt_secure_header_file_path.clear()
        self.txt_request_file_path.clear()
        self.txt_num_of_retries.clear()
        self.txt_response_time.clear()
        self.txt_host_release_version.clear()
        self.txt_host_name.clear()

        self.check_box_assessment_body.setChecked(False)
        self.check_box_assessment_head.setChecked(False)
        self.check_box_assessment_url.setChecked(False)
        self.check_box_sec_risk_csrf.setChecked(False)
        self.check_box_sec_risk_xss.setChecked(False)
        self.check_box_sec_risk_auth_bypass.setChecked(False)
        self.check_box_sec_risk_dir_traversal.setChecked(False)
        self.check_box_sec_risk_buffer_overflow.setChecked(False)

        self.radio_btn_secure_header_false.setChecked(False)
        self.radio_btn_secure_header_true.setChecked(False)

    def start_assessment(self):
        """Method to start assessment"""
        # record execution start date
        start_date_time = datetime.datetime.now()

        # get json requests
        base_requests = get_requests(self.config['request_file_path'])

        # create instance of RequestClass
        http_requests = Requests(wait_time=self.config['response_time'],
                                 num_of_retries=self.config['number_of_retries'])
        http_requests.check_device(self.config['protocol_type'], self.config['ip_address'])

        # create instance of WebAssessment db
        assessment_db = WebAssessmentDb(self.config['ip_address'])

        if 'secure_header_file_path' in self.config.keys():
            active_header_audit = ActiveHeaderAudit(self.config['secure_header_file_path'])
        else:
            active_header_audit = False

        for security_risk in self.config['security_risks']:

            if security_risk == 'xss':
                Xss(
                    config_dict=self.config, base_requests=base_requests, http_requests=http_requests,
                    database=assessment_db, active_header_audit=active_header_audit
                )

            elif security_risk == 'bufferoverflow':
                BufferOverflow(
                    config_dict=self.config, base_requests=base_requests, http_requests=http_requests,
                    database=assessment_db, active_header_audit=active_header_audit
                )

            elif security_risk == 'csrf':
                Csrf(
                    config_dict=self.config, base_requests=base_requests, http_requests=http_requests,
                    database=assessment_db, active_header_audit=active_header_audit
                )

            elif security_risk == 'directorytraversal':
                DirectoryTraversal(
                    config_dict=self.config, base_requests=base_requests, http_requests=http_requests,
                    database=assessment_db, active_header_audit=active_header_audit
                )

            elif security_risk == 'authorizationbypass':
                AuthorizationByPass(
                    config_dict=self.config, base_requests=base_requests, http_requests=http_requests,
                    database=assessment_db, active_header_audit=active_header_audit
                )

        if active_header_audit:
            self.config['security_risks'].append(active_header_audit)

        # record end date time
        end_date_time = datetime.datetime.now()

        # create instance of Reports class
        reports = Reports(
            database=assessment_db, vulnerability_type=self.config['security_risks'],
            config_dict=self.config, start_date_time=start_date_time, end_date_time=end_date_time
        )

        return_data = reports.get_reports()
        if len(return_data) > 0:
            QMessageBox.information(self, "information", f"Reports generated in {return_data}")
        else:
            QMessageBox.information(self, "information", "Reports has been not generated")

        # close database connection
        assessment_db.close_connection()

        self.show()

    def generate_report(self):
        report_form = Report()
        report_form.exec_()

