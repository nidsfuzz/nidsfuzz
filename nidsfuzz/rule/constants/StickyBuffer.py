import enum
from enum import unique

from rule.constants.Proto import Proto


@unique
class StickyBuffer(enum.StrEnum):

    HTTP_URI = 'http_uri'
    HTTP_HEADER = 'http_header'
    HTTP_COOKIE = 'http_cookie'
    HTTP_CLIENT_BODY = 'http_client_body'
    HTTP_PARAM = 'http_param'
    HTTP_METHOD = 'http_method'
    HTTP_VERSION = 'http_version'
    HTTP_TRAILER = 'http_trailer'
    HTTP_TRUE_IP = 'http_true_ip'
    HTTP_STAT_CODE = 'http_stat_code'
    HTTP_STAT_MSG = 'http_stat_msg'
    HTTP_RAW_BODY = 'http_raw_body'
    HTTP_RAW_URI = 'http_raw_uri'
    HTTP_RAW_HEADER = 'http_raw_header'
    HTTP_RAW_COOKIE = 'http_raw_cookie'
    HTTP_RAW_REQUEST = 'http_raw_request'
    HTTP_RAW_STATUS = 'http_raw_status'
    HTTP_RAW_TRAILER = 'http_raw_trailer'

    # SIP_METHOD = 'sip_method'
    # SIP_VERSION = 'sip_version'
    # SIP_URI = 'sip_uri'
    SIP_HEADER = 'sip_header'
    SIP_BODY = 'sip_body'
    # SIP_STAT_CODE = 'sip_stat_code'
    # SIP_STAT_MSG = 'sip_stat_msg'

    PKT_DATA = 'pkt_data'
    RAW_DATA = 'raw_data'
    FILE_DATA = 'file_data'
    JS_DATA = 'js_data'
    VBA_DATA = 'vba_data'
    BASE64_DATA = 'base64_data'

    @classmethod
    def lookup(cls, buffer: str) -> 'StickyBuffer':
        for member in cls:
            if member.value == buffer.lower():
                return member
        raise ValueError(f'{buffer} is not a valid sticky buffer.')

    @classmethod
    def all(cls) -> set[str]:
        all_buffers = set()
        for member in cls:
            all_buffers.add(member.value)
        return all_buffers

    def proto(self) -> Proto | None:
        proto = self.name.split("_", 1)[0]
        try:
            return Proto.lookup(proto)
        except ValueError:
            return None


if __name__ == '__main__':
    buffer = StickyBuffer.HTTP_HEADER
    print(f'The value of buffer: {buffer.value}')
    print(f'The proto of buffer: {buffer.proto()}')

    print(f'all sticky buffers: {StickyBuffer.all()}')



