import requests
import urllib.request
import re
import logging
from http import cookiejar
from urllib3 import disable_warnings
from pathlib import Path
from assessment.helpers import create_folder


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')

log_path = Path(create_folder())/"requests.log"
file_handler = logging.FileHandler(log_path)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class BlockAll(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False


class Requests:
    """Class to handle http operations"""
    def __init__(self, wait_time, num_of_retries):
        disable_warnings()
        # create http session
        self.session = requests.Session()
        # put ssl verification to false
        self.session.verify = False
        self.session.cookies.set_policy(BlockAll())

        # get proxy settings and set it to request
        system_proxy = urllib.request.getproxies()
        if len(system_proxy) > 0:
            self.session.proxies = system_proxy

        # load the configuration
        self.wait_time = float(wait_time)
        self.num_of_retries = float(num_of_retries)

        self.session_id = None
        self.csrf_token = None
        self.header = dict()

    def check_device(self, protocol, ip_address):
        """method to check session id or csrf token is present
         if mentioned values is present add them to a data type"""
        try:
            url = f"{protocol}://{ip_address}"
            response = self.session.get(url, timeout=self.wait_time)

            self.session_id = self.check_cookie(response.headers)
            self.csrf_token = self.check_csrf(response.text)
        except requests.exceptions.RequestException:
            logger.exception('Not able get response from check device method')

    def modify_header(self, **kwargs):
        """method to modify headers"""
        content_length = int()
        if 'body' in kwargs.keys():
            content_length = len(kwargs['body'])

        content_length_index = str()
        cookie_index = str()
        host_index = str()
        referer_index = str()
        origin_index = str()
        protocol = kwargs['protocol']
        ip = kwargs['ip']

        header = kwargs['header']
        #  change header values
        for head in header:
            if str(head).startswith("Content-Length"):
                content_length_index = header.index(head)

            if str(head).startswith("Cookie"):
                cookie_index = header.index(head)

            if str(head).startswith("Host"):
                host_index = header.index(head)

            if str(head).startswith("Referer"):
                referer_index = header.index(head)

            if str(head).startswith("Origin"):
                origin_index = header.index(head)

        if len(str(cookie_index)) > 0:
            header.pop(cookie_index)
            header.insert(cookie_index, f"Cookie:{self.session_id}")

        if len(str(host_index)) > 0:
            header.pop(host_index)
            header.insert(host_index, f"Host:{ip}")

        if len(str(referer_index)) > 0:
            referer = re.sub(r"(https|http)://(.+?)/", f"{protocol}://{ip}/", header[referer_index])
            header.pop(referer_index)
            header.insert(referer_index, referer)

        if len(str(origin_index)) > 0:
            header.pop(origin_index)
            header.insert(origin_index, f"Origin:{protocol}://{ip}")

        if 'body' in kwargs.keys():
            if len(str(content_length_index)) > 0:
                header.pop(content_length_index)
                header.insert(content_length_index, f"Content-Length:{content_length}")
        else:
            header.pop(content_length_index)

        # convert header from list to dictionary data type
        header_dict = dict()
        for head in header:
            header_dict[head.split(":", 1)[0].strip(" ")] = head.split(":", 1)[1].strip(" ")

        return header_dict

    def get_request(self, **kwargs):
        """method to get requests"""
        url = kwargs['url']  # url were the request has to be made
        ip = str(kwargs['ip_address'])  # ip address
        protocol = str(kwargs['protocol'])  # protocol
        # header = self.modify_header(header=kwargs['headers'], ip=ip, protocol=protocol)  # header

        request_url = f"{protocol}://{ip}{url}"

        try:

            if 'header' in kwargs.keys():
                response = self.session.get(request_url, headers=kwargs['header'], timeout=self.wait_time)

            else:
                response = self.session.get(request_url, timeout=self.wait_time)

            return response

        except requests.exceptions.RequestException:

            if 'header' in kwargs.keys():
                return self.retry_request("get", request_url, "", kwargs['header'])
            else:
                return self.retry_request("get", request_url, "", "")

    def send_requests(self, **kwargs):
        """method to analyse the header and depends on the method
         select the applicable method and send the request"""
        ip = str(kwargs['ip_address'])  # ip address
        protocol = str(kwargs['protocol'])  # protocol
        body = str(kwargs['body'])  # modified body

        if 'header_attack' in kwargs.keys() or 'url_attack' in kwargs.keys():
            method = str(kwargs['method'])  # method
            url_path = str(kwargs['url_path'])  # url were the request has to be made
            header = kwargs['header']

        else:
            method = str(kwargs['headers'][0]).split(" ")[0]    # method
            url_path = str(kwargs['headers'][0]).split(" ")[1]  # url were the request has to be made
            header = self.modify_header(header=kwargs['headers'][1:], body=body, ip=ip, protocol=protocol)  # header

        request_url = f"{protocol}://{ip}{url_path}"

        # if csrf token is present add it into the body
        csrf_token = re.search(r"[cC][sS][rR][fF][tT][oO][kK][eE][nN]", body)

        if csrf_token:
            csrf_value = re.search(r"[cC][sS][rR][fF][tT][oO][kK][eE][nN]=(.*?)&", body)
            if not csrf_value:
                csrf_value = re.search(r"[cC][sS][rR][fF][tT][oO][kK][eE][nN]=(.*?)$", body)

            old_csrf = f"{csrf_token.group()}={csrf_value.group(1)}"
            new_csrf = f"{csrf_token.group()}={self.csrf_token}"

            body = body.replace(old_csrf, new_csrf)

        if method.lower() == "post":
            return self.post(request_url, header, body)

        elif method.lower() == "put":
            return self.put(request_url, header, body)

    def post(self, request_url, header, body):
        """method to send the post requests"""
        try:
            response = self.session.post(request_url, body, headers=header, timeout=self.wait_time)
            return response
        except requests.exceptions.RequestException:
            return self.retry_request("post", request_url, body, header)

    def put(self, request_url, header, body):
        """method to send the post requests"""
        try:
            response = self.session.put(request_url, body, headers=header, timeout=self.wait_time)
            return response
        except requests.exceptions.RequestException:
            return self.retry_request("put", request_url, body, header)

    def get(self, request_url, header, body):
        """method to send the get requests"""
        try:
            response = self.session.get(request_url, headers=header, timeout=self.wait_time)
            return response
        except requests.exceptions.RequestException:
            return self.retry_request("get", request_url, body, header)

    def retry_request(self, request_type, request_url, body, header):
        """method to retry the requests"""
        response = None
        for retry in range(int(self.num_of_retries)):
            try:
                if request_type == "post":
                    response = self.session.post(request_url, body, headers=header, timeout=self.wait_time)
                elif request_type == "put":
                    response = self.session.put(request_url, body, headers=header, timeout=self.wait_time)
                elif request_type == "get":
                    response = self.session.get(request_url, timeout=self.wait_time)

            except requests.exceptions.RequestException:
                logger.exception('Not able to initiate retry request')

            if response is not None:
                break

        if response is None:
            return 000
        else:
            return response

    @staticmethod
    def check_cookie(header):
        try:
            response_cookie = header['Set-Cookie'].split(';')
            return response_cookie[0]
        except KeyError:
            return "Not Available"

    @staticmethod
    def check_csrf(response):
        split_response = response.split('\r\n')

        for res in split_response:
            val = re.search(r"[cC][sS][rR][fF][tT][oO][kK][eE][nN]", res)
            if val:
                csrf_value = re.search(r"\svalue=\"(.+?)\"", res).group(1)
                if csrf_value is '':
                    return "Not Available"
                else:
                    return csrf_value

        return "Not Available"
