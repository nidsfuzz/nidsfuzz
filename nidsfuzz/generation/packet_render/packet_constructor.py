class PacketConstructor:

    def __init__(self, buffers: dict[str: str], protocol: str, packet_type: str):
        self.buffers = buffers
        self.protocol = protocol.upper()
        self.packet_type = packet_type.upper()

    def get_packet(self) -> str:
        if self.protocol == "HTTP":
            return self.concatenate(self.get_buffer_payloads_http())
        else:
            raise Exception(f"Unsupported protocol: {self.protocol}.")

    def get_buffer_payloads_http(self) -> dict[str, str]:
        if self.packet_type == "REQUEST":
            http_request_default_buffers = {
                'http_method': 'GET',
                'http_space1': ' ',
                'http_uri': '/connecttest.txt',
                'http_space2': ' ',
                'http_version': 'HTTP/1.1',
                'http_crlf1': '\r\n',
                'http_header': 'Connection: Close\r\nUser-Agent: Microsoft NCSI\r\n'
                               'Host: www.msftconnecttest.com\r\nContent-Type: text\r\n',
                'http_crlf2': '\r\n',
                'http_client_body': ''
            }
            # Use buffers from rules to replace default buffers.
            for buffer in http_request_default_buffers.keys():
                if buffer in self.buffers.keys():
                    http_request_default_buffers[buffer] = self.buffers[buffer]
                    self.buffers.pop(buffer)
            for buffer, content in self.buffers.items():
                http_request_default_buffers['http_client_body'] += content
            # Calculate and set Content-Length.
            if not http_request_default_buffers['http_header'].endswith("\r\n"):
                http_request_default_buffers['http_header'] += "\r\n"
            http_request_default_buffers[
                'http_header'] = (f"Content-Length: {len(http_request_default_buffers['http_client_body'])}\r\n" +
                                  http_request_default_buffers['http_header'])
            return http_request_default_buffers
        elif self.packet_type == "RESPONSE":
            http_response_default_buffers = {
                'http_version': 'HTTP/1.1',
                'http_space1': ' ',
                'http_stat_code': '200',
                'http_space2': ' ',
                'http_stat_msg': 'OK',
                'http_crlf1': '\r\n',
                'http_header': 'Date: Thu, 29 Aug 2024 02:17:27 GMT\r\nConnection: close\r\n'
                               'Content-Type: text/plain\r\nCache-Control: max-age=30, must-revalidate\r\n',
                'http_crlf2': '\r\n',
                'http_raw_body': ''
            }
            # Use buffers from rules to replace default buffers.
            for buffer in http_response_default_buffers.keys():
                if buffer in self.buffers.keys():
                    http_response_default_buffers[buffer] = self.buffers[buffer]
                    self.buffers.pop(buffer)
            for buffer, content in self.buffers.items():
                http_response_default_buffers['http_raw_body'] += content
            # Calculate and set Content-Length.
            if not http_response_default_buffers['http_header'].endswith("\r\n"):
                http_response_default_buffers['http_header'] += "\r\n"
            http_response_default_buffers[
                'http_header'] = (f"Content-Length: {len(http_response_default_buffers['http_raw_body'])}\r\n" +
                                  http_response_default_buffers['http_header'])
            return http_response_default_buffers
        else:
            raise Exception("Unsupported packet type.")

    @staticmethod
    def concatenate(buffer_payloads: dict[str, str]) -> str:
        """
        Concatenate all buffers to get data packet.

        Args:
            buffer_payloads: buffer names and their payload

        Returns: data packet from buffer_payloads

        """
        packet = ""
        for _, content in buffer_payloads.items():
            packet += content
        return packet


if __name__ == "__main__":
    buffers = {'http_stat_code': '30', 'http_header': '\nLocation:\nLocation:'}
    packet_constructor = PacketConstructor(buffers, "HTTP", "RESPONSE")
    print(packet_constructor.get_packet())
