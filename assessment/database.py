import sqlite3
import logging

from datetime import datetime
from pathlib import Path

from assessment.helpers import create_folder

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')

log_path = str(Path(create_folder())/"database.log")
file_handler = logging.FileHandler(log_path)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class WebAssessmentDb:
    """Class to create ,access and modify the database"""
    def __init__(self, ip_address, gen_report=False):
        try:
            if not gen_report:
                ip_adr = ip_address
                date_time = datetime.now()
                database_name = date_time.strftime("%Y-%m-%d %H-%M-%S")
                self.db_name = f"{ip_adr} {database_name}"
                path = str(Path(create_folder())/f"{self.db_name}.db")
                self.conn = sqlite3.connect(path)
            else:
                self.db_name = ip_address
                self.conn = sqlite3.connect(self.db_name)

            self.cursor = self.conn.cursor()

        except sqlite3.Error:
            logger.exception('Unable to initialize the database')

        self.create_table()

    def create_table(self):
        """function to create table 'WebAssessment' if not exists in database"""
        try:
            self.cursor.execute(
                'CREATE TABLE IF NOT EXISTS WebAssessment (DATETIME TEXT, HOST TEXT, URL TEXT,'
                'METHOD TEXT, STATUS_CODE TEXT, ATTACK_TYPE TEXT,SUB_ATTACK_TYPE TEXT, TAG TEXT, ACTUAL_DATA TEXT,'
                'PAYLOAD TEXT, CURRENT_DATA TEXT, RESULT TEXT, ACT_HEADER_ADT_RSP, ACT_HEADER_ADT_RSL);'
            )

        except sqlite3.Error:
            logger.exception('Unable to create WebAssessment table')

    def insert_value(self, data):
        """method to insert values in 'WebAssessment' table"""
        try:
            self.cursor.execute(
                'INSERT INTO WebAssessment (DATETIME, HOST, URL, METHOD, STATUS_CODE, ATTACK_TYPE, SUB_ATTACK_TYPE,'
                'TAG, ACTUAL_DATA, PAYLOAD, CURRENT_DATA, RESULT, ACT_HEADER_ADT_RSP, ACT_HEADER_ADT_RSL)'
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', data
            )

            self.conn.commit()

        except sqlite3.Error:
            logger.exception('Unable to insert data in WebAssessment table')

    def get_reports(self, attack_type):
        """Method to get values to generate report based on attack_type"""
        try:

            if attack_type in ['xss', 'bufferoverflow', 'csrf', 'dir_traversal', 'authorizationbypass']:

                self.cursor.execute(
                    'SELECT DATETIME, HOST, URL, METHOD, STATUS_CODE, SUB_ATTACK_TYPE, TAG, ACTUAL_DATA, PAYLOAD,'
                    'CURRENT_DATA, RESULT FROM WebAssessment '
                    'WHERE ATTACK_TYPE=\'%s\'' % attack_type
                )

                rows = self.cursor.fetchall()
                return rows

            elif attack_type == 'secureheadercheck':

                self.cursor.execute(
                    '''
                    SELECT DATETIME, HOST, URL, METHOD, STATUS_CODE, ACT_HEADER_ADT_RSP, ACT_HEADER_ADT_RSL FROM
                    WebAssessment WHERE ACT_HEADER_ADT_RSL != \'False\' AND ACT_HEADER_ADT_RSL != \'No Response\'
                    AND ACT_HEADER_ADT_RSL != \'Not Audited\'
                    '''
                )

                rows = self.cursor.fetchall()
                return rows

        except sqlite3.Error:
            logger.exception('Unable to get data from get report method')

    def close_connection(self):
        """method to close database connection"""
        try:
            self.conn.close()

        except sqlite3.Error:
            logger.exception("Unable to close sqlite3 connection")

