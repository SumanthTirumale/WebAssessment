from assessment.helpers import insert_data, filter_url, print_message, print_status_code
import re
import copy
from socket import getfqdn

from colorama import init
from termcolor import colored

VEP = "vep"
SOL = "sol"
SIRIUS_CLASSIC = 'siriusclassic'
CSRF = 'csrf'
APOLLO = 'apollo'
PHOENIX = 'phoenix'

SUB_ATTACK_TYPE = ['header', 'url', 'body']
SUPPORTED_HTTP_METHODS = ['get', 'put', 'post']


class Csrf:
    """Class to xss vulnerability attack"""
    def __init__(self, **kwargs):
        self.config_dict = kwargs['config_dict']
        self.base_requests = kwargs['base_requests']
        self.http_requests = kwargs['http_requests']
        self.active_header_audit = kwargs['active_header_audit']
        self.db = kwargs['database']
        self.host_name = getfqdn(self.config_dict['ip_address']).split(".")[0]
        self.domain_name = "testnetwork.com"

        self.payloads = [
            '',
            'null',
            f"{self.config_dict['protocol_type']}://{self.config_dict['ip_address'][:-1]}",
            f"http://{self.config_dict['ip_address']}", "NPI253114", "NPI253114.tesnetwork.com"
        ]

        if str(self.config_dict['protocol_type']).lower() == "http":
            self.payloads.pop(3)

        self.valid_payload = [
            f"{self.config_dict['protocol_type']}://{self.config_dict['ip_address']}",
            f"{self.host_name}",
            f"{self.host_name}.{self.domain_name}"
        ]

        self.header = dict()

        # total number of attacks
        self.attack_count = len(self.base_requests['baseRequests'])

        # additional variables to hold the audited data
        self.url_path = ''
        self.method = ''
        self.sub_attack_type = ''

        init()

        self.attack()

    def add_data(self, **data):
        """method to add data into database"""
        additional_val = {
            'db': self.db,
            'host': self.config_dict['ip_address'],
            'attack_type': CSRF,
            'url': self.url_path,
            'method': self.method,
            'sub_attack_type': self.sub_attack_type
        }
        # merge two dictionaries and send it to insert data function
        insert_data(**{**data, **additional_val})

    def modify_header(self, **kwargs):
        """method to modify header"""
        # convert header type from list to dictionary
        header = kwargs['header'][1:]
        body = kwargs['body']
        cookie = kwargs['cookie']

        for head in header:
            _tmp = head.split(":", 1)   # split the header
            self.header[_tmp[0].replace(" ", "")] = _tmp[1].replace(" ", "")

        for key, value in self.header.items():

            if key == "Content-Length":
                self.header[key] = str(len(body))

            if key == "Cookie":
                self.header[key] = cookie

            if key == "Host":
                self.header[key] = self.config_dict['ip_address']

            if key == "Referer":
                referer = re.sub(
                    r"(https|http)://(.+?)/",
                    f"{self.config_dict['protocol_type']}://{self.config_dict['ip_address']}/",
                    value
                )

                self.header[key] = referer

            if key == "Origin":
                self.header[key] = f"{self.config_dict['protocol_type']}://" \
                    f"{self.config_dict['ip_address']}"

    def header_attack(self, body, raw_header):
        """Method start header attack"""

        self.method = str(raw_header[0]).split(" ")[0]  # method
        self.url_path = str(raw_header[0]).split(" ")[1]  # url were the request has to be made
        self.sub_attack_type = SUB_ATTACK_TYPE[0]  # sub attack type header

        if self.method.lower() in SUPPORTED_HTTP_METHODS:

            # Origin and Referer invalid value Check
            for csrf_headers in ["Origin", "Referer"]:

                count = 0
                for payload in self.payloads:

                    tmp_header = copy.deepcopy(self.header)

                    if csrf_headers == "Origin":
                        if "Origin" not in tmp_header.keys():
                            tmp_header["Origin"] = payload
                        else:
                            tmp_header[csrf_headers] = payload
                    else:

                        if count == 2:

                            if "Referer" not in tmp_header.keys():
                                tmp_header["Referer"] = ""

                            tmp_header[csrf_headers] = re.sub(
                                r"(https|http)://(.+?)/",
                                f"{self.config_dict['protocol_type']}://{self.config_dict['ip_address'][:-1]}/",
                                tmp_header[csrf_headers]
                            )

                        elif count == 3:
                            if "Referer" not in tmp_header.keys():
                                tmp_header["Referer"] = ""

                            tmp_header[csrf_headers] = re.sub(
                                r"(https|http)://(.+?)/",
                                f"http://{self.config_dict['ip_address']}/",
                                tmp_header[csrf_headers]
                            )

                        elif count == 4:
                            if "Referer" not in tmp_header.keys():
                                tmp_header["Referer"] = ""

                            tmp_header[csrf_headers] = re.sub(
                                r"(https|http)://(.+?)/",
                                f"NPI253114/",
                                tmp_header[csrf_headers]
                            )

                        elif count == 5:
                            if "Referer" not in tmp_header.keys():
                                tmp_header["Referer"] = ""

                            tmp_header[csrf_headers] = re.sub(
                                r"(https|http)://(.+?)/",
                                f"NPI253114.tesnetwork.com/",
                                tmp_header[csrf_headers]
                            )

                        else:
                            tmp_header[csrf_headers] = payload

                    print_message(self.sub_attack_type, self.method, self.url_path)

                    # send http request
                    if self.method.lower() in ['post', 'put']:
                        response = self.http_requests.send_requests(
                            method=self.method, url_path=self.url_path, ip_address=self.config_dict['ip_address'],
                            protocol=self.config_dict['protocol_type'], body=body, header=tmp_header, header_attack=True
                        )

                    else:
                        response = self.http_requests.get_request(
                            url=self.url_path, ip_address=self.config_dict['ip_address'],
                            protocol=self.config_dict['protocol_type'], header=tmp_header
                        )

                    print_status_code(response)

                    if response == 000:
                        response_code = "No Response"
                    else:
                        response_code = response.status_code

                    header = str()
                    for head_key, head_value in tmp_header.items():
                        header = f"{header}{head_key}:{head_value}\n"

                    active_header_result = "None"
                    active_header_response = "None"

                    if not str(response_code).startswith("4"):

                        if response_code == 000:
                            response_code = 000
                            response_header = "None"

                            if self.active_header_audit:
                                active_header_result = "No Response"
                                active_header_response = "No Response"

                        else:
                            response_code = response_code
                            response_header = str()

                            for k, v in response.headers.items():
                                response_header = f"{response_header}{k} : {v}\n"

                            if self.active_header_audit:
                                active_header_result = self.active_header_audit.check_response_headers(
                                    response.headers)
                                active_header_response = response_header

                        if self.active_header_audit:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data=header, payload=payload,
                                current_data=response_header, result="Vulnerable",
                                act_header_adt_rsp=active_header_response, act_header_adt_rsl=active_header_result
                            )

                        else:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data=header, payload=payload,
                                current_data=response_header, result="Vulnerable"
                            )
                    else:
                        response_header = str()

                        for k, v in response.headers.items():
                            response_header = f"{response_header}{k} : {v}\n"

                        if self.active_header_audit:
                            active_header_result = self.active_header_audit.check_response_headers(response.headers)
                            active_header_response = response_header

                            self.add_data(
                                status_code=response.status_code, tag="None", actual_data=header,
                                payload=payload, current_data=response_header, result="False Positive",
                                act_header_adt_rsp=active_header_response, act_header_adt_rsl=active_header_result
                            )

                        else:

                            self.add_data(
                                status_code=response.status_code, tag="None", actual_data=header,
                                payload=payload, current_data=response_header, result="False Positive"
                            )

                    count += 1

            # Origin and Referer valid value Check
            for csrf_headers in ["Origin", "Referer"]:

                count = 0
                for payload in self.valid_payload:

                    tmp_header = copy.deepcopy(self.header)
                    if csrf_headers == "Origin":
                        if "Origin" not in tmp_header.keys():
                            tmp_header["Origin"] = payload
                        else:
                            tmp_header[csrf_headers] = payload
                    else:

                        if count == 0:
                            if "Referer" not in tmp_header.keys():
                                tmp_header["Referer"] = ""

                            tmp_header[csrf_headers] = re.sub(
                                r"(https|http)://(.+?)/",
                                f"{self.config_dict['protocol_type']}://{self.config_dict['ip_address']}/",
                                tmp_header[csrf_headers]
                            )

                        elif count == 1:
                            if "Referer" not in tmp_header.keys():
                                tmp_header["Referer"] = ""

                            tmp_header[csrf_headers] = re.sub(
                                r"(https|http)://(.+?)/",
                                f"{self.host_name}/",
                                tmp_header[csrf_headers]
                            )

                        elif count == 2:
                            if "Referer" not in tmp_header.keys():
                                tmp_header["Referer"] = ""

                            tmp_header[csrf_headers] = re.sub(
                                r"(https|http)://(.+?)/",
                                f"{self.host_name}.{self.domain_name}/",
                                tmp_header[csrf_headers]
                            )

                    print_message(self.sub_attack_type, self.method, self.url_path)

                    # send http request
                    if self.method.lower() in ['post', 'put']:
                        response = self.http_requests.send_requests(
                            method=self.method, url_path=self.url_path, ip_address=self.config_dict['ip_address'],
                            protocol=self.config_dict['protocol_type'], body=body, header=tmp_header,
                            header_attack=True
                        )

                    else:
                        response = self.http_requests.get_request(
                            url=self.url_path, ip_address=self.config_dict['ip_address'],
                            protocol=self.config_dict['protocol_type'], header=tmp_header
                        )

                    print_status_code(response)

                    if response == 000:
                        response_code = response
                    else:
                        response_code = response.status_code

                    header = str()
                    for head_key, head_value in tmp_header.items():
                        header = f"{header}{head_key}:{head_value}\n"

                    active_header_result = "None"
                    active_header_response = "None"

                    if not str(response_code).startswith("2"):

                        if response == 000:
                            response_code = response_code
                            response_header = "None"

                            if self.active_header_audit:
                                active_header_result = "No Response"
                                active_header_response = "No Response"

                        else:
                            response_code = response_code
                            response_header = str()

                            for k, v in response.headers.items():
                                response_header = f"{response_header}{k} : {v}\n"

                            if self.active_header_audit:
                                active_header_result = self.active_header_audit.check_response_headers(
                                    response.headers)
                                active_header_response = response_header

                        if self.active_header_audit:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data=header, payload=payload,
                                current_data=response_header, result="Vulnerable",
                                act_header_adt_rsp=active_header_response,
                                act_header_adt_rsl=active_header_result
                            )

                        else:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data=header, payload=payload,
                                current_data=response_header, result="Vulnerable"
                            )
                    else:
                        response_header = str()

                        for k, v in response.headers.items():
                            response_header = f"{response_header}{k} : {v}\n"

                        if self.active_header_audit:
                            active_header_result = self.active_header_audit.check_response_headers(
                                response.headers)
                            active_header_response = response_header

                            self.add_data(
                                status_code=response.status_code, tag="None", actual_data=header,
                                payload=payload, current_data=response_header, result="False Positive",
                                act_header_adt_rsp=active_header_response,
                                act_header_adt_rsl=active_header_result
                            )

                        else:

                            self.add_data(
                                status_code=response.status_code, tag="None", actual_data=header,
                                payload=payload, current_data=response_header, result="False Positive"
                            )

                    count += 1

        else:
            print(colored(f"{self.method} has not been implemented in tool!!!!", "red"))

    def attack(self):

        print(colored("######################## CSRF Attack ########################", 'cyan'))

        if 'url_exclusion' in self.config_dict.keys():

            excluded_url = self.config_dict['url_exclusion']

            if type(excluded_url) is not list:
                excluded_url = [excluded_url]

            base_requests = filter_url(self.base_requests, excluded_url)

        else:
            base_requests = self.base_requests

        for base_request in base_requests['baseRequests']:

            # modify the headers only applicable for header and url assessment
            self.modify_header(
                header=base_request['headers'], body=base_request['bodyRaw'],
                cookie=self.http_requests.session_id
            )

            self.header_attack(
                base_request['bodyRaw'], base_request['headers']
            )
