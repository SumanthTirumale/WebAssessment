from platform import system
from subprocess import call, PIPE
import re
import json
from datetime import datetime
import os
from colorama import init
from termcolor import colored
from pathlib import Path

# printer types
# below variables are used in inject payload function
VEP = "vep"
SOL = "sol"
SIRIUS_CLASSIC = 'siriusclassic'
APOLLO = 'apollo'
PHOENIX = 'phoenix'


def ping(ip_address):
    """ ping to the host and check host is alive or dead and send the response """
    param = "-n" if system().lower() == "windows" else "-c"
    command = ['ping', param, '1', ip_address]

    return call(command, stdout=PIPE) == 0


def check_file(path):
    """ function to check file is exists and return boolean value"""
    if os.path.isfile(path):
        return True
    else:
        return False


def get_requests(path):
    """function to get requests from json file and return requests in dictionary format"""
    with open(path, 'r') as base_json:
        return json.load(base_json)


def get_payloads(attack_type):
    """function to get payloads from txt file and return payloads in list format"""
    path = str()

    if attack_type == "xss":
        path = str(Path(__file__).absolute().parent.parent / "assessment/payloads/xss.txt")

    elif attack_type == "bufferoverflow":
        path = str(Path(__file__).absolute().parent.parent / "assessment/payloads/BufferOverflow.txt")

    elif attack_type == "common_parameters":
        path = str(Path(__file__).absolute().parent.parent / "assessment/payloads/common_traversal.txt")

    elif attack_type == "common_traversal":
        path = str(Path(__file__).absolute().parent.parent / "assessment/payloads/common_traversal.txt")

    with open(path, 'r') as f:
        temp_list = f.readlines()

    return [payload.strip() for payload in temp_list]


def inject_payload(**kwargs):
    """function to inject the payloads in body or headers and return the modified body"""

    payload = kwargs['payload']
    body_array = kwargs['body_array']
    raw_body = kwargs['raw_body']
    printer_type = kwargs['printer_type']

    if printer_type in [VEP, APOLLO, PHOENIX]:
        return_body = raw_body.replace(
            f"{body_array[0]}={body_array[1]}",
            f"{body_array[0]}={payload}", 1
        )

        current_val = body_array[1]
        tag = body_array[0]

        return tag, current_val, return_body

    elif printer_type in [SOL, SIRIUS_CLASSIC]:
        return_body = raw_body.replace(
            f"<{body_array[0]}>{body_array[1]}</{body_array[0]}>",
            f"<{body_array[0]}>{payload}</{body_array[0]}>", 1
        )

        current_val = body_array[1]
        tag = body_array[0]

        return tag, current_val, return_body


def insert_data(**kwargs):
    """function to insert intruded data in database"""
    if 'act_header_adt_rsp' in kwargs.keys() and 'act_header_adt_rsl' in kwargs.keys():
        act_header_adt_rsp = kwargs['act_header_adt_rsp']
        act_header_adt_rsl = kwargs['act_header_adt_rsl']
    else:
        act_header_adt_rsp = "Not Audited"
        act_header_adt_rsl = "Not Audited"

    kwargs['db'].insert_value(
        (
            str(datetime.now()),
            str(kwargs['host']),
            str(kwargs['url']),
            str(kwargs['method']),
            str(kwargs['status_code']),
            str(kwargs['attack_type']),
            str(kwargs['sub_attack_type']),
            str(kwargs['tag']),
            str(kwargs['actual_data']),
            str(kwargs['payload']),
            str(kwargs['current_data']),
            str(kwargs['result']),
            str(act_header_adt_rsp),
            str(act_header_adt_rsl),

        )
    )


def create_folder():
    """function to create traffic monitor directory"""
    data_store_path = '~/Documents/WebAssessment'
    path = Path(data_store_path).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def analyze_data(**kwargs):
    """function to analyze the response data """
    payload = kwargs['payload']
    tag = kwargs['tag']
    response = kwargs['response']
    printer_type = kwargs['printer_type']

    if printer_type in [VEP, APOLLO, PHOENIX]:
        # VEP, APOLLO, PHOENIX printer logic
        html_parsed_data = html_parser(tag, response)

        if html_parsed_data == "Nothing Found":
            return html_parsed_data, "False Positive"
        else:
            pattern = r"""{exp}""".format(exp=payload)

            if type(html_parsed_data) is list:
                tmp = list()
                for data in html_parsed_data:
                    val = re.findall(re.escape(pattern), data)
                    tmp.extend(val)

                val = "\n".join(tmp)

            else:
                val = re.findall(re.escape(pattern), html_parsed_data)

            if val:
                return val, "Vulnerable"

            else:
                owasp_xss = ''
                owasp_xss_pattern = re.compile(r"(<|>|\"|\'|/|&\s)")

                if type(html_parsed_data) is list:
                    tmp = list()
                    for data in html_parsed_data:
                        val = owasp_xss_pattern.findall(data)
                        tmp.extend(val)
                    owasp_xss = tmp

                else:
                    val = owasp_xss_pattern.search(html_parsed_data)
                    if val:
                        owasp_xss = val.group()

                if owasp_xss:
                    return owasp_xss, "Vulnerable"
                else:
                    return html_parsed_data, "False Positive"

    elif printer_type in [SOL, SIRIUS_CLASSIC]:
        # SOL AND SIRIOUS CLASSIC printer logic
        xml_parsed_data = xml_parser(tag, response)

        if xml_parsed_data == "Nothing Found":
            return xml_parsed_data, "False Positive"
        else:
            pattern = r"""{exp}""".format(exp=payload)

            if type(xml_parsed_data) is list:
                tmp = list()
                for data in xml_parsed_data:
                    val = re.findall(re.escape(pattern), data)
                    tmp.extend(val)

                val = "\n".join(tmp)

            else:
                val = re.findall(re.escape(pattern), xml_parsed_data)

            if val:
                return val, "Vulnerable"

            else:
                owasp_xss = ''
                owasp_xss_pattern = re.compile(r"(<|>|\"|\'|/|&\s)")

                if type(xml_parsed_data) is list:
                    tmp = list()
                    for data in xml_parsed_data:
                        val = owasp_xss_pattern.findall(data)
                        tmp.extend(val)
                    owasp_xss = "\n".join(tmp)

                else:
                    val = owasp_xss_pattern.search(xml_parsed_data)
                    if val:
                        owasp_xss = val.group()

                if owasp_xss:
                    return owasp_xss, "Vulnerable"
                else:
                    return "\n".join(xml_parsed_data), "False Positive"


def html_parser(tag, response):
    """function to parse the html data to check reflected payload"""
    stripped_html = str()

    input_regex = re.compile('(<[I|i][N|n][P|p][U|u][T|t] (.+?|.*)>)')

    input_textarea = re.compile('(<[T|t][E|e][X|x][T|t][A|a][R|r][E|e][A|a] (.+?|.*)>(.*|.+?)'
                                '</[T|t][E|e][X|x][T|t][A|a][R|r][E|e][A|a]>)')

    input_option = re.compile('(<[S|s][E|e][L|l][E|e][C|c][T|t] (.+?)>(.+?)</[S|s][E|e][L|l][E|e][C|c][T|t]>)')

    payload = "Nothing Found"

    for html in str(response).split("\n"):
        if html:
            html = html.rstrip().lstrip()

            if html != '':
                stripped_html = stripped_html + html

    # input tag operation
    if payload == "Nothing Found":
        if input_regex.findall(stripped_html):
            for html_input_tag in input_regex.findall(stripped_html):
                if tag in html_input_tag[0]:
                    value_search = re.search(r'[V|v][A|a][L|l][U|u][E|e]=\"(.+?|.*)\"', html_input_tag[0])
                    if value_search:
                        payload = value_search.group(1)

    # text area tag operation
    if payload == "Nothing Found":
        if input_textarea.findall(stripped_html):
            for html_text_area_tag in input_textarea.findall(stripped_html):
                if tag in html_text_area_tag[0]:
                    payload = html_text_area_tag[2]

    # option tag operation
    if payload == "Nothing Found":
        option_tag_1 = re.compile(
            r'(<[O|o][P|p][T|t][I|i][O|o][N|n] (.+?|.*)>(.*|.+?)</[O|o][P|p][T|t][I|i][O|o][N|n]>)')
        option_tag_2 = re.compile(r'(<[O|o][P|p][T|t][I|i][O|o][N|n] (.+?|.*)>(.*|.+?)<)')

        if input_option.findall(stripped_html):
            for html_option_tag in input_option.findall(stripped_html):
                if tag in html_option_tag[0]:

                    if option_tag_1.findall(html_option_tag[0]):
                        for option in option_tag_1.findall(html_option_tag[0]):
                            select_reg = re.compile(r">(.+?)</")

                            for i in option[0].split("><"):
                                if "selected" in i.lower():
                                    if select_reg.search(i):
                                        payload = select_reg.search(i).group(1)

                    elif option_tag_2.findall(html_option_tag[0]):
                        for option in option_tag_2.findall(html_option_tag[0]):
                            for i in option[0][1:].split('<'):
                                select_reg = re.compile(r"[S|s][E|e][L|l][E|e][C|c][T|t][E|e][D|d](.+)")
                                if select_reg.search(i):
                                    payload = select_reg.search(i).group(1).split(">", 1)[1]

    return payload


def xml_parser(tag, response):
    payload = 'Nothing Found'
    pattern = re.compile(r"<" + tag + ">(.*?)</" + tag + ">")

    matched_tag = pattern.findall(response)

    if len(matched_tag) > 0:
        return matched_tag
    else:
        return payload


def get_status_code_value(status_code):
    """function to return appropriate status code value from the dictionary"""
    status_code_dict = {
        "100": "Continue", "101": "Switching Protocols", "200": "OK", "201": "Created",
        "202": "Accepted", "203": "Non-authoritative Information", "204": "No Content",
        "205": "Reset Content", "206": "Partial Content", "300": "Multiple Choices",
        "301": "Moved Permanently", "302": "Found", "303": "See Other", "304": "Not Modified",
        "305": "Use Proxy", "306": "Unused", "307": "Temporary Redirect", "400": "Bad Request",
        "401": "Unauthorized", "402": "Payment Required", "403": "Forbidden", "404": "Not Found",
        "405": "Method Not Allowed", "406": "Not Acceptable", "407": "Proxy Authentication Required",
        "408": "Request Timeout", "409": "Conflict", "410": "Gone", "411": "Length Required",
        "412": "Precondition Failed", "413": "Request Entity Too Large", "414": "Request-url Too Long",
        "415": "Unsupported Media Type", "416": "Requested Range Not Satisfiable",
        "417": "Expectation Failed", "500": "Internal Server Error", "501": "Not Implemented",
        "502": "Bad Gateway", "503": "Service Unavailable", "504": "Gateway Timeout",
        "505": "HTTP Version Not Supported"
    }

    return status_code_dict[status_code]


def custom_print(pattern, data):
    """ prints messages in proper format in console"""
    char = 120 - len(data)

    subtract = char / 2

    subtract_divisible = char % 2
    add_extra = subtract - 15

    if subtract_divisible != 0:

        right_asterisk = subtract + 1 + add_extra
        left_asterisk = 15

    else:

        right_asterisk = subtract + add_extra
        left_asterisk = 15

    print("\n%s %s %s" % (pattern * (int(left_asterisk) - 1), data, pattern * (int(right_asterisk) - 1)))


def change_exclusion_header_format(header):
    """ Method to modify the exclusion header format.
     ex: content-type to Content-Type"""

    if type(header) is list:
        tmp_list = list()

        for head in header:
            tmp = head.split("-")

            val = str()
            for t in tmp:
                val = val + "-" + t.capitalize()

            tmp_list.append(val.replace("-", "", 1))

        return tmp_list

    else:
        tmp = header.split("-")
        val = str()
        for t in tmp:
            val = val + "-" + t.capitalize()

        return val.replace("-", "", 1)


def check_header_vulnerabilities(header, payload, attack_type):
    """Function To check if any vulnerabilities are present in header"""
    return_data = str()

    if attack_type == "xss" or attack_type == "bufferoverflow":
        for key, value in header.items():
            if payload in value:
                return_data = f"{return_data}{key} : {value}\n"

        if len(return_data) > 0:
            return return_data, "Vulnerable"
        else:
            return "Nothing Found", "False Positive"


def filter_url(base_requests, excluded_url):
    tmp_list = list()

    for base_request in base_requests['baseRequests']:
        url_path = str(base_request['headers'][0]).split(" ")[1].lower()
        if url_path not in excluded_url:
            tmp_list.append(base_request)

    return {'baseRequests': tmp_list}


def print_message(sub_attack_type, method, url):
    print(colored(f"{sub_attack_type} {method} {url}", "green"))


def print_status_code(response):
    if response == "Not Implemented" or response == 000:
        print(colored(f"{response}\n", "yellow"))
    else:
        print(colored(f"{response.status_code}\n", "yellow"))