from generation.grammars.DefaultGrammar import DefaultGrammar


class SIPGrammar(DefaultGrammar):

    def populate(self, part_fields: dict[str, bytes]):
        super().populate(part_fields)

        if not self.request_fields['sip_header'].endswith(b"\r\n"):
            self.request_fields['sip_header'] += b"\r\n"
        self.request_fields['sip_header'] = (
                self.request_fields['sip_header'] +
                f"Content-Length: {len(self.request_fields['sip_body'])}\r\n".encode("utf-8"))

        if not self.response_fields['sip_header'].endswith(b"\r\n"):
            self.response_fields['sip_header'] += b"\r\n"
        self.response_fields['sip_header'] = (
                self.response_fields['sip_header'] +
                f"Content-Length: {len(self.response_fields['sip_body'])}\r\n".encode("utf-8"))

    @classmethod
    def templates(cls, pkt_type: str) -> dict[str, bytes]:
        match pkt_type.upper():
            case "REQUEST":
                return {
                    'sip_method': b'INVITE',
                    'sip_space1': b' ',
                    'sip_uri': b'sip:bob@biloxi.com',
                    'sip_space2': b' ',
                    'sip_version': b'SIP/2.0',
                    'sip_crlf1': b'\r\n',
                    'sip_header':
                        b'Via: SIP/2.0/TCP client.atlanta.example.com:5060;branch=z9hG4bK74bf9\r\n'
                        b'Max-Forwards: 70\r\n'
                        b'From: Alice <sip:alice@atlanta.example.com>;tag=9fxced76sl\r\n'
                        b'To: Bob <sip:bob@biloxi.example.com>\r\n'
                        b'Call-ID: 3848276298220188511@atlanta.example.com\r\n'
                        b'CSeq: 2 INVITE\r\n'
                        b'Content-Type: application/sdp\r\n',
                    'sip_crlf2': b'\r\n',
                    'sip_body': b'',
                }
            case "RESPONSE":
                return {
                    'sip_version': b'SIP/2.0',
                    'sip_space1': b' ',
                    'sip_stat_code': b'100',
                    'sip_space2': b' ',
                    'sip_stat_msg': b'trying -- your call is important to us',
                    'sip_crlf1': b'\r\n',
                    'sip_header':
                        b'Via: SIP/2.0/UDP 10.135.0.12:5060;branch=z9hG4bKhye0bem20x.nx8hnt\r\n'
                        b'Max-Forwards: 70\r\n'
                        b'From: "Calling User" <sip:151@10.135.0.1:5060>;tag=m3l2hbp\r\n'
                        b'To: <sip:001234567890@10.135.0.1:5060;user=phone>;tag=b27e1a1d33761e85846fc98f5f3a7e58.d5d4\r\n'
                        b'Call-ID: ud04chatv9q@10.135.0.1\r\n'
                        b'CSeq: 10691 ACK\r\n'
                        b'User-Agent: Wildix W-AIR 03.55.00.24 9c7514340722\r\n',
                    'sip_crlf2': b'\r\n',
                    'sip_body': b'',
                }
            case _:
                raise NotImplementedError