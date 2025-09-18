from generation.grammars.DefaultGrammar import DefaultGrammar


class HTTPGrammar(DefaultGrammar):

    def populate(self, part_fields: dict[str, bytes]):
        super().populate(part_fields)

        # Check the format of request packet
        if not self.request_fields['http_header'].endswith(b"\r\n"):
            self.request_fields['http_header'] += b"\r\n"
        self.request_fields['http_header'] = (
                f"Content-Length: {len(self.request_fields['http_client_body'])}\r\n".encode("utf-8") +
                self.request_fields['http_header'])
        # Check the format of response packet
        if not self.response_fields['http_header'].endswith(b"\r\n"):
            self.response_fields['http_header'] += b"\r\n"
        self.response_fields['http_header'] = (
                f"Content-Length: {len(self.response_fields['http_raw_body'])}\r\n".encode("utf-8") +
                self.response_fields['http_header'])


    @classmethod
    def templates(cls, pkt_type: str) -> dict[str, bytes]:
        match pkt_type.upper():
            case "REQUEST":
                return {
                    'http_method': b'GET',
                    'http_space1': b' ',
                    'http_uri': b'/connecttest.txt',
                    'http_space2': b' ',
                    'http_version': b'HTTP/1.1',
                    'http_crlf1': b'\r\n',
                    'http_header': b'Connection: Close\r\nUser-Agent: Microsoft NCSI\r\n'
                                   b'Host: www.msftconnecttest.com\r\nContent-Type: text\r\n',
                    'http_crlf2': b'\r\n',
                    'http_client_body': b''
                }
            case "RESPONSE":
                return {
                    'http_version': b'HTTP/1.1',
                    'http_space1': b' ',
                    'http_stat_code': b'200',
                    'http_space2': b' ',
                    'http_stat_msg': b'OK',
                    'http_crlf1': b'\r\n',
                    'http_header': b'Date: Thu, 29 Aug 2024 02:17:27 GMT\r\nConnection: close\r\n'
                                   b'Content-Type: text/plain\r\nCache-Control: max-age=30, must-revalidate\r\n',
                    'http_crlf2': b'\r\n',
                    'http_raw_body': b''
                }
            case _:
                raise NotImplementedError
