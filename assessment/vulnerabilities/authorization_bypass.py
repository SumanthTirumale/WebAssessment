from assessment.helpers import insert_data, filter_url, print_message, print_status_code, change_exclusion_header_format

import re
import copy

from colorama import init
from termcolor import colored

APOLLO = 'apollo'
PHOENIX = 'phoenix'
VEP = "vep"
SOL = "sol"
SIRIUS_CLASSIC = 'siriusclassic'

SUB_ATTACK_TYPE = ['header', 'url', 'body']
SUPPORTED_HTTP_METHODS = ['get', 'put', 'post']


class AuthorizationByPass:

    def __init__(self, **kwargs):
        self.config_dict = kwargs['config_dict']
        self.base_requests = kwargs['base_requests']
        self.http_requests = kwargs['http_requests']
        self.active_header_audit = kwargs['active_header_audit']
        self.db = kwargs['database']
        self.header = dict()

        # total number of attacks
        self.attack_count = len(self.base_requests['baseRequests'])

        # additional variables to hold the audited data
        self.url_path = ''
        self.method = ''
        self.sub_attack_type = ''

        # Bypass header
        self.bypass_headers = ["Cookie", "Authorization"]

        init()

        self.attack()

    def add_data(self, **data):
        """method to add data into database"""
        additional_val = {
            'db': self.db,
            'host': self.config_dict['ip_address'],
            'attack_type': 'authorizationbypass',
            'url': self.url_path,
            'method': self.method,
            'sub_attack_type': self.sub_attack_type
        }
        # merge two dictionaries and send it to insert data function
        insert_data(**{**data, **additional_val})

    def modify_header(self, **kwargs):
        # convert header type from list to dictionary
        header = kwargs['header'][1:]
        body = kwargs['body']

        for head in header:
            _tmp = head.split(":", 1)  # split the header
            self.header[_tmp[0].replace(" ", "")] = _tmp[1].replace(" ", "")

        # remove cookie and authorization and header exclusion from header dictionary
        exclusion_headers = change_exclusion_header_format(self.config_dict['header_exclusion'])

        if type(exclusion_headers) is not list:
            exclusion_headers = [exclusion_headers]

        for bypass_header in self.bypass_headers:
            try:
                self.header.pop(bypass_header)
            except KeyError:
                pass

        for exclusion_header in exclusion_headers:
            try:
                self.header.pop(exclusion_header)
            except KeyError:
                pass

        for key, value in self.header.items():
            if key == "Content-Length":
                self.header[key] = str(len(body))

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

    def body_attack(self, **data):
        body = data['body']
        raw_header = data['raw_header']

        self.method = str(raw_header[0]).split(" ")[0]  # method
        self.url_path = str(raw_header[0]).split(" ")[1]  # url were the request has to be made
        self.sub_attack_type = SUB_ATTACK_TYPE[0]  # sub attack type is body

        if self.method.lower() in SUPPORTED_HTTP_METHODS:
            tmp_header = copy.deepcopy(self.header)

            print_message(self.sub_attack_type, self.method, self.url_path)

            url = f"{self.config_dict['protocol_type']}://{self.config_dict['ip_address']}{self.url_path}"

            if self.method.lower() == "put":
                response = self.http_requests.put(
                    request_url=url, header=self.header, body=body
                )

            elif self.method.lower() == "post":
                response = self.http_requests.post(
                    request_url=url, header=self.header, body=body
                )

            else:
                response = self.http_requests.get(
                    request_url=url, header=self.header, body=body
                )

            print_status_code(response)

            header = str()
            for head_key, head_value in tmp_header.items():
                header = f"{header}{head_key}:{head_value}\n"

            active_header_result = "None"
            active_header_response = "None"

            if response == 000 or str(response.status_code).startswith("2") \
                    or str(response.status_code).startswith("5"):

                if response == 000:
                    response_code = 000
                    response_header = "None"

                    if self.active_header_audit:
                        active_header_result = "No Response"
                        active_header_response = "No Response"

                else:

                    response_code = response.status_code
                    response_header = ""

                    for k, v in response.headers.items():
                        response_header = f"{response_header}{k} : {v}\n"

                    if self.active_header_audit:
                        active_header_result = self.active_header_audit.check_response_headers(
                            response.headers)
                        active_header_response = response_header

                if self.active_header_audit:

                    self.add_data(
                        status_code=response_code, tag="None", actual_data=header, payload="No Payload",
                        current_data=response_header, result="Vulnerable",
                        act_header_adt_rsp=active_header_response,
                        act_header_adt_rsl=active_header_result
                    )

                else:

                    self.add_data(
                        status_code=response_code, tag="None", actual_data=header, payload="No Payload",
                        current_data=response_header, result="Vulnerable",
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
                        payload="No Payload",
                        current_data=response_header, result="False Positive",
                        act_header_adt_rsp=active_header_response,
                        act_header_adt_rsl=active_header_result
                    )

                else:

                    self.add_data(
                        status_code=response.status_code, tag="None", actual_data=header,
                        payload="No Payload",
                        current_data=response_header, result="False Positive"
                    )

        else:
            print(colored(f"{self.method} has not been implemented in tool!!!!", "red"))

    def attack(self):
        print(colored("######################## Authorization ByPass Attack ########################", 'cyan'))

        if 'url_exclusion' in self.config_dict.keys():

            excluded_url = self.config_dict['url_exclusion']

            if type(excluded_url) is not list:
                excluded_url = [excluded_url]

            base_requests = filter_url(self.base_requests, excluded_url)

        else:
            base_requests = self.base_requests

        for base_request in base_requests['baseRequests']:

            self.modify_header(header=base_request['headers'], body=base_request['bodyRaw'])

            self.body_attack(body=base_request['bodyRaw'], raw_header=base_request['headers'])