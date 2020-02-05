from assessment.helpers import get_payloads, insert_data, inject_payload, analyze_data, print_message, print_status_code
from assessment.helpers import filter_url
import re
from colorama import init
from termcolor import colored

VEP = "vep"
SOL = "sol"
SIRIUS_CLASSIC = 'siriusclassic'
Dir_Traversal = ["common_parameters", "common_traversal"]
APOLLO = 'apollo'
PHOENIX = 'phoenix'

SUB_ATTACK_TYPE = ['header', 'url', 'body']
SUPPORTED_HTTP_METHODS = ['get', 'put', 'post']


class DirectoryTraversal:
    """Class to xss vulnerability attack"""
    def __init__(self, **kwargs):
        self.config_dict = kwargs['config_dict']
        self.base_requests = kwargs['base_requests']
        self.http_requests = kwargs['http_requests']
        self.active_header_audit = kwargs['active_header_audit']

        self.db = kwargs['database']

        self.header = dict()

        self.payload = self.get_payload()
        self.body_payload = get_payloads(Dir_Traversal[1])

        self.url_audit = False
        self.header_audit = False
        self.body_audit = False

        # additional variables to hold the audited data
        self.url_path = ''
        self.method = ''
        self.sub_attack_type = ''

        init()

        self.attack()

    @staticmethod
    def get_payload():
        common_parameters = get_payloads(Dir_Traversal[0])
        common_traversals = get_payloads(Dir_Traversal[1])
        tmp_list = list()

        for common_parameter in common_parameters:
            for common_traversal in common_traversals:
                tmp_list.append(f"{common_parameter}={common_traversal}")

        return tmp_list

    def add_data(self, **data):
        """method to add data into database"""
        additional_val = {
            'db': self.db,
            'host': self.config_dict['ip_address'],
            'attack_type': 'dir_traversal',
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

    def url_attack(self, body, raw_header, referer_url=None):
        self.method = str(raw_header[0]).split(" ")[0]  # method
        url_path = str(raw_header[0]).split(" ")[1]  # url were the request has to be made
        self.sub_attack_type = SUB_ATTACK_TYPE[1]  # sub attack type is url

        # capture the content length by sending the requests as it is

        # send http request

        if self.method.lower() in SUPPORTED_HTTP_METHODS:

            if self.method.lower() in ['put', 'post']:
                response = self.http_requests.send_requests(
                    method=self.method, url_path=url_path, ip_address=self.config_dict['ip_address'],
                    protocol=self.config_dict['protocol_type'], body=body, header=self.header, url_attack=True
                )

                if self.config_dict['printer_type'] in [SOL, SIRIUS_CLASSIC]:
                    response = self.http_requests.get_request(
                        url=url_path, ip_address=self.config_dict['ip_address'],
                        protocol=self.config_dict['protocol_type']
                    )

                elif self.config_dict['printer_type'] in [PHOENIX, APOLLO]:
                    response = self.http_requests.get_request(
                        url=referer_url, ip_address=self.config_dict['ip_address'],
                        protocol=self.config_dict['protocol_type']

                    )

            else:
                response = self.http_requests.get_request(
                    url=self.url_path, ip_address=self.config_dict['ip_address'],
                    protocol=self.config_dict['protocol_type'], header=self.header
                )

            if response == 000:
                content_length = "No Response"
            else:
                content_length = len(response.text)

            for payload in self.payload:

                intruder_url = url_path + "?" + payload

                self.url_path = intruder_url

                print_message(self.sub_attack_type, self.method, self.url_path)

                # send http request
                if self.method.lower() in ['post', 'put']:
                    response = self.http_requests.send_requests(
                        method=self.method, url_path=self.url_path, ip_address=self.config_dict['ip_address'],
                        protocol=self.config_dict['protocol_type'], body=body, header=self.header, url_attack=True
                    )

                else:
                    response = self.http_requests.get_request(
                        url=self.url_path, ip_address=self.config_dict['ip_address'],
                        protocol=self.config_dict['protocol_type'], header=self.header
                    )

                print_status_code(response)

                active_header_result = "None"
                active_header_response = "None"

                if response == 000 or str(response.status_code).startswith("2") or \
                        str(response.status_code).startswith("5"):

                    if response == 000:
                        response_code = 000

                        if self.active_header_audit:
                            active_header_result = "No Response"
                            active_header_response = "No Response"

                    else:
                        response_code = response.status_code

                        if self.active_header_audit:
                            response_header = str()

                            for k, v in response.headers.items():
                                response_header = f"{response_header}{k} : {v}\n"

                            active_header_result = self.active_header_audit.check_response_headers(response.headers)
                            active_header_response = response_header

                    if response_code == 000:
                        current_data = "No Response"
                        rsp_content_length = "No Response"

                    else:
                        current_data = response.text
                        rsp_content_length = len(response.text)

                    # print(f"Default length : {content_length}")
                    # print(f"After Assess length : {rsp_content_length}")

                    if rsp_content_length != content_length:

                        if self.active_header_audit:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data="None", payload=payload,
                                current_data=current_data, result="Vulnerable",
                                act_header_adt_rsp=active_header_response,
                                act_header_adt_rsl=active_header_result
                            )

                        else:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data="None", payload=payload,
                                current_data=current_data, result="Vulnerable"
                            )
                    else:

                        if self.active_header_audit:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data="None", payload=payload,
                                current_data=current_data, result="False Positive",
                                act_header_adt_rsp=active_header_response,
                                act_header_adt_rsl=active_header_result
                            )

                        else:

                            self.add_data(
                                status_code=response_code, tag="None", actual_data="None", payload=payload,
                                current_data=current_data, result="False Positive"
                            )

                else:

                    if self.active_header_audit:
                        response_header = str()

                        for k, v in response.headers.items():
                            response_header = f"{response_header}{k} : {v}\n"

                        active_header_result = self.active_header_audit.check_response_headers(response.headers)
                        active_header_response = response_header

                        self.add_data(
                            status_code=response.status_code, tag="None", actual_data="None", payload=payload,
                            current_data=response.text, result="False Positive",
                            act_header_adt_rsp=active_header_response, act_header_adt_rsl=active_header_result
                        )

                    else:

                        self.add_data(
                            status_code=response.status_code, tag="None", actual_data="None",
                            payload=payload, current_data=response.text, result="False Positive"
                        )

        else:
            print(colored(f"{self.method} has not been implemented in tool!!!!", "red"))

    def body_attack(self, **data):
        """Method to attack request body"""

        payloads = self.body_payload
        body = data['body']
        raw_header = data['raw_header']
        body_array = data['body_array']

        if 'referer_url' in data.keys():
            referer_url = data['referer_url']
        else:
            referer_url = 'None'

        self.method = str(raw_header[0]).split(" ")[0]  # method
        self.url_path = str(raw_header[0]).split(" ")[1]  # url were the request has to be made
        self.sub_attack_type = SUB_ATTACK_TYPE[2]  # sub attack type is body

        # capture the content length by sending the requests as it is

        if self.method.lower() in SUPPORTED_HTTP_METHODS:

            if self.method.lower() in ['put', 'post']:
                response = self.http_requests.send_requests(
                    method=self.method, url_path=self.url_path, ip_address=self.config_dict['ip_address'],
                    protocol=self.config_dict['protocol_type'], body=body, header=self.header, url_attack=True
                )

                if self.config_dict['printer_type'] in [SOL, SIRIUS_CLASSIC]:
                    response = self.http_requests.get_request(
                        url=self.url_path, ip_address=self.config_dict['ip_address'],
                        protocol=self.config_dict['protocol_type']
                    )

                elif self.config_dict['printer_type'] in [PHOENIX, APOLLO]:
                    response = self.http_requests.get_request(
                        url=referer_url, ip_address=self.config_dict['ip_address'],
                        protocol=self.config_dict['protocol_type']

                    )

                if response == 000:
                    content_length = "No Response"
                else:
                    content_length = len(response.text)

                for payload in payloads:

                    for key, value in body_array.items():

                        print_message(self.sub_attack_type, self.method, self.url_path)

                        tag, current_val, return_body = inject_payload(
                            payload=payload, body_array=[key, value],
                            raw_body=body, printer_type=self.config_dict['printer_type']
                        )

                        # send http request
                        response = self.http_requests.send_requests(
                            body=return_body,
                            headers=raw_header,
                            ip_address=self.config_dict['ip_address'],
                            protocol=self.config_dict['protocol_type']
                        )

                        print_status_code(response)

                        if response == 000:

                            if self.active_header_audit:
                                active_header_result = "No Response"
                                active_header_response = "No Response"

                                self.add_data(
                                    status_code=000, tag=tag, actual_data=current_val, payload=payload,
                                    current_data="No Response", result="Vulnerable",
                                    act_header_adt_rsp=active_header_response,
                                    act_header_adt_rsl=active_header_result
                                )

                            else:

                                self.add_data(
                                    status_code=000, tag=tag, actual_data=current_val, payload=payload,
                                    current_data="No Response", result="Vulnerable"
                                )
                        else:

                            if self.config_dict['printer_type'] in [SOL, SIRIUS_CLASSIC]:
                                response = self.http_requests.get_request(
                                    url=self.url_path, ip_address=self.config_dict['ip_address'],
                                    protocol=self.config_dict['protocol_type']
                                )

                            elif self.config_dict['printer_type'] in [PHOENIX, APOLLO]:
                                response = self.http_requests.get_request(
                                    url=referer_url, ip_address=self.config_dict['ip_address'],
                                    protocol=self.config_dict['protocol_type']

                                )

                            if str(response.status_code).startswith("2"):

                                rsp_content_length = len(response.text)

                                # print(f"content length : {content_length}")
                                # print(f"response content length : {rsp_content_length}")

                                if rsp_content_length != content_length:

                                    current_data, result = analyze_data(
                                        payload=payload, tag=tag,
                                        response=response.text, printer_type=self.config_dict['printer_type']
                                    )

                                else:

                                    current_data = response.text
                                    result = "False Positive"

                                if self.active_header_audit:

                                    response_header = str()

                                    for k, v in response.headers.items():
                                        response_header = f"{response_header}{k} : {v}\n"

                                    active_header_result = self.active_header_audit.check_response_headers(
                                        response.headers)
                                    active_header_response = response_header

                                    self.add_data(
                                        status_code=response.status_code, tag=tag, actual_data=current_val,
                                        payload=payload,
                                        current_data=current_data, result=result,
                                        act_header_adt_rsp=active_header_response,
                                        act_header_adt_rsl=active_header_result
                                    )

                                else:

                                    self.add_data(
                                        status_code=response.status_code, tag=tag, actual_data=current_val,
                                        payload=payload,
                                        current_data=current_data, result=result
                                    )

                            else:

                                if self.active_header_audit:

                                    response_header = str()

                                    for k, v in response.headers.items():
                                        response_header = f"{response_header}{k} : {v}\n"

                                    active_header_result = self.active_header_audit.check_response_headers(
                                        response.headers)
                                    active_header_response = response_header

                                    self.add_data(
                                        status_code=response.status_code, tag=tag, actual_data=current_val,
                                        payload=payload,
                                        current_data=response.text, result="False Positive",
                                        act_header_adt_rsp=active_header_response,
                                        act_header_adt_rsl=active_header_result
                                    )

                                else:

                                    self.add_data(
                                        status_code=response.status_code, tag=tag, actual_data=current_val,
                                        payload=payload,
                                        current_data=response.text, result="False Positive"
                                    )

        else:
            print(colored(f"{self.method} has not been implemented in tool!!!!", "red"))

    def attack(self):

        print(colored("######################## Directory Traversal Attack ########################", 'cyan'))

        if 'url' in self.config_dict['assessment_type']:
            self.url_audit = True

        if 'header' in self.config_dict['assessment_type']:
            self.header_audit = True

        if 'body' in self.config_dict['assessment_type']:
            self.body_audit = True

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

            if self.url_audit:

                if self.config_dict['printer_type'] in [APOLLO, PHOENIX]:

                    self.url_attack(base_request['bodyRaw'], base_request['headers'], base_request['url'])

                else:

                    self.url_attack(base_request['bodyRaw'], base_request['headers'])

            if self.body_audit:

                if self.config_dict['printer_type'] in [APOLLO, PHOENIX]:

                    self.body_attack(
                        body=base_request['bodyRaw'], raw_header=base_request['headers'],
                        body_array=base_request['bodyArray'], referer_url=base_request['url']
                    )

                else:

                    self.body_attack(
                        body=base_request['bodyRaw'], raw_header=base_request['headers'],
                        body_array=base_request['bodyArray']
                    )

