from configparser import ConfigParser    # import config parser module
from assessment.helpers import check_file, ping
import sys


class Configuration:

    CONFIG_FILE_PATH = "config.ini"
    SUPPORTED_PROTOCOL_TYPES = ['http', 'https']
    SUPPORTED_PRINTER_TYPES = ['vep', 'sol', 'siriusclassic', 'apollo', 'phoenix']
    SUPPORTED_VULNERABILITY_TYPES = ['xss', 'bufferoverflow', 'csrf', 'directorytraversal', 'authorizationbypass']
    SUPPORTED_ASSESSMENT_TYPES = ['header', 'body', 'url']

    def __init__(self):
        self.config_dict = dict()
        self.get_configuration()
        self.check_configuration()

    def get_configuration(self):
        """method to get the data from configuration file and convert it into a dictionary and return the values"""
        if check_file(Configuration.CONFIG_FILE_PATH):
            parser = ConfigParser()  # create a config parser instance
            parser.read(Configuration.CONFIG_FILE_PATH)
            for key in parser['DEFAULT']:
                config_value = str(parser['DEFAULT'][key]).lower().replace(" ", "")

                if "," in config_value:
                    config_value = config_value.split(",")

                self.config_dict[str(key).replace(" ", "_")] = config_value

        else:
            sys.exit("config.ini file is not present !!!")

    def check_configuration(self):
        """method to check configuration details"""
        secure_header_flag = False
        # IP Address
        if 'ip_address' in self.config_dict.keys():
            # check victim ip is alive
            if not ping(self.config_dict['ip_address']):
                sys.exit(f"{self.config_dict['ip_address']} is not alive please check the victim ip address !!!")
        else:
            sys.exit("'IP Address' field is not present in config.ini !!!")

        # Printer Name
        if 'printer_name' in self.config_dict.keys():
            if not len(self.config_dict['printer_name']) > 0:
                sys.exit("Please enter the printer name in config.ini !!!")
        else:
            sys.exit("'Printer Name' field is not present in config.ini !!!")

        # Release Version
        if 'release_version' in self.config_dict.keys():
            if not len(self.config_dict['release_version']) > 0:
                sys.exit("Please enter the release version in config.ini !!!")
        else:
            sys.exit("'Release Version' field is not present in config.ini !!!")

        # Protocol Type
        if 'protocol_type' in self.config_dict.keys():
            if not type(self.config_dict['protocol_type']) is str:
                sys.exit("Multiple values are not supported for 'Protocol Type' field !!!")

            else:
                if self.config_dict['protocol_type'] not in Configuration.SUPPORTED_PROTOCOL_TYPES:
                    sys.exit("Supported Protocols are HTTP, HTTPS please enter any mentioned protocol !!!")
        else:
            sys.exit("'Protocol Type' field is not present in config.ini !!!")

        # Printer Type
        if 'printer_type' in self.config_dict.keys():
            if not type(self.config_dict['printer_type']) is str:
                sys.exit("Multiple values are not supported for 'Printer Type' field !!!")

            else:
                if self.config_dict['printer_type'] not in Configuration.SUPPORTED_PRINTER_TYPES:
                    sys.exit("Defined Printer is currently not supported !!!\n"
                             "Supported printer types are VEP, SOL, SIRIUS CLASSIC")
        else:
            sys.exit("'Protocol Type' field is not present in config.ini !!!")

        # Response Time
        if 'response_time' in self.config_dict.keys():
            if not len(self.config_dict['response_time']) > 0:
                sys.exit("Please enter the response time in config.ini !!!")
        else:
            sys.exit("'Response Time' field is not present in config.ini !!!")

        # Number Of Retries
        if 'number_of_retries' in self.config_dict.keys():
            if not len(self.config_dict['number_of_retries']) > 0:
                sys.exit("Please enter the number of retries in config.ini !!!")
        else:
            sys.exit("'Number Of Retries' field is not present in config.ini !!!")

        # Request File Path
        if 'request_file_path' in self.config_dict.keys():
            if not len(self.config_dict['request_file_path']) > 0:
                sys.exit("Please enter the Request File Path in config.ini !!!")
            else:
                if not check_file(self.config_dict['request_file_path']):
                    sys.exit(f"{self.config_dict['request_file_path']} file is not present !!!")
        else:
            sys.exit("'Request File Path' field is not present in config.ini !!!")

        # assessment_type
        if 'assessment_type' in self.config_dict.keys():
            if type(self.config_dict['assessment_type']) is str:
                if self.config_dict['assessment_type'] not in Configuration.SUPPORTED_ASSESSMENT_TYPES:
                    sys.exit(f"{self.config_dict['assessment_type']} is not supported in Assessment Type !!!")

            else:
                for assessment in self.config_dict['assessment_type']:
                    if assessment not in Configuration.SUPPORTED_ASSESSMENT_TYPES:
                        sys.exit(f"{self.config_dict['assessment_type']} is not supported in Assessment Type !!!")

        else:
            sys.exit("'Assessment Type' field is not present in config.ini !!!")

        # vulnerability_type
        if 'vulnerability_type' in self.config_dict.keys():
            if type(self.config_dict['vulnerability_type']) is str:
                if self.config_dict['vulnerability_type'] not in Configuration.SUPPORTED_VULNERABILITY_TYPES:
                    sys.exit(f"{self.config_dict['vulnerability_type']} is not supported in Vulnerability Type!!!")

            else:
                for vulnerability in self.config_dict['vulnerability_type']:
                    if vulnerability not in Configuration.SUPPORTED_VULNERABILITY_TYPES:
                        sys.exit(f"{self.config_dict['vulnerability_type']} is not supported in Vulnerability Type!!!")

        else:
            sys.exit("'Vulnerability Type' field is not present in config.ini !!!")

        # Secure Header Check
        if 'secure_header_check' in self.config_dict.keys():
            if self.config_dict['secure_header_check'] in ['true', 'false']:

                if self.config_dict['secure_header_check'] == 'true':
                    secure_header_flag = True
                elif self.config_dict['secure_header_check'] == 'false':
                    secure_header_flag = False

            else:
                sys.exit(f"{self.config_dict['secure_header_check']} is not supported in Secure Header Check Field !!!")

        # Secureheader File Path
        if secure_header_flag:
            if 'secureheader_file_path' in self.config_dict.keys():
                if not len(self.config_dict['secureheader_file_path']) > 0:
                    sys.exit("Please enter the secure header file path in config.ini !!!")
                else:
                    if not check_file(self.config_dict['secureheader_file_path']):
                        sys.exit(f"{self.config_dict['secureheader_file_path']} file is not present !!!")
            else:
                sys.exit("'Secureheader File Path' field is not present in config.ini !!!")
        else:
            self.config_dict.pop('secureheader_file_path', None)

        # Url Exclusion
        if 'url_exclusion' not in self.config_dict.keys():
            self.config_dict.pop('url_exclusion', None)

        # Header Exclusion
        if 'header_exclusion' not in self.config_dict.keys():
            self.config_dict.pop('header_exclusion', None)
