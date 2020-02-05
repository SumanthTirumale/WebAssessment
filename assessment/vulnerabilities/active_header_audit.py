from assessment.helpers import get_requests


class ActiveHeaderAudit:
    """ Class to passive audit the response header"""

    def __init__(self, json_path):
        """initialization"""
        # get passive header audit json and save it to a dictionary data type
        self._json_dict = get_requests(json_path)

    def check_response_headers(self, header):
        """ Method to check security headers in response headers"""

        infected_headers = header

        _missing_headers = list()
        _value_mismatch_headers = list()

        # loop passive header audit dict
        for header_json_key, header_json_val in self._json_dict.items():

            # condition to check security header present in response headers
            if header_json_key in infected_headers.keys():

                if "Content-Security-Policy" in header_json_key:

                    rsp_content = infected_headers[header_json_key].split(";")
                    rsp_content = [i.strip(" ") for i in rsp_content]

                    tmp_json_content = list()
                    for key, val in header_json_val.items():
                        tmp_json_content.append(f"{key} {' '.join(val)}")

                    diff_values = set(rsp_content) - set(tmp_json_content)

                    if len(diff_values) > 0:
                        _value_mismatch_headers.append(
                            f"{header_json_key} value mismatch\n Current Value : {','.join(rsp_content)}\n"
                            f"Expected Value : {','.join(header_json_val)}\n")

                elif "Cache-Control" in header_json_key:

                    # convert json cache control value from string to list data type
                    _tmp_rsp_cache_list = infected_headers[header_json_key].split(",")
                    _tmp_rsp_cache_list = [i.strip(" ") for i in _tmp_rsp_cache_list]

                    # find the difference between json cache control and response cache control
                    diff_values = set(_tmp_rsp_cache_list) - set(header_json_val)

                    if len(diff_values) > 0:
                        _value_mismatch_headers.append(
                            f"{header_json_key} value mismatch\n Current Value : {','.join(_tmp_rsp_cache_list)}\n"
                            f"Expected Value : {','.join(header_json_val)}\n")
                else:

                    if header_json_val not in infected_headers[header_json_key]:
                        _value_mismatch_headers.append(
                            f"{header_json_key} value mismatch\n Current Value : {infected_headers[header_json_key]}\n"
                            f"Expected Value : {header_json_val}\n")
            else:
                _value_mismatch_headers.append(f"{header_json_key} header is not present\n")

            if "Set-Cookie" in infected_headers.keys():

                if "Content-Length" not in infected_headers.keys():
                    _value_mismatch_headers.append("Content-Length header is missing When Set-Cookie is present in "
                                                   "header\n")

                if "Content-Type" not in infected_headers.keys():
                    _value_mismatch_headers.append("Content-Type header is missing When Set-Cookie is present in "
                                                   "header\n")

        if len(_value_mismatch_headers) > 0:
            return "\n".join(_value_mismatch_headers)
        else:
            return False
