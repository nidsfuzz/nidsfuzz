import struct
from typing import Generator


def hex2str(hex_str: str) -> str:
    """
    Converts a hex string to a string of hex digits.

    @see https://tool.oschina.net/commons?type=4

    Example Usage:
    --------
    >>> result = hex2str("41 42")  # \x41 = A, \x42 = B
    >>> print(result)  # AB
    """
    res = ""
    for hex_value in hex_str.split():
        res += chr(int(hex_value, 16))
    return res


def write_traffic(file_path: str, request: bytes, response: bytes):
    with open(file_path, 'ab') as f:
        f.write(struct.pack('!I', len(request)))
        f.write(request)
        f.write(struct.pack('!I', len(response)))
        f.write(response)


def read_traffic(file_path: str) -> Generator[tuple[bytes, bytes], None, None]:
    with open(file_path, 'rb') as f:
        while True:
            length_data = f.read(4)
            if not length_data:
                break  # Reach the end of the file
            request_length = struct.unpack('!I', length_data)[0]
            request = f.read(request_length)

            length_data = f.read(4)
            if not length_data:
                raise ValueError("Unexpected end of file when reading response length.")
            response_length = struct.unpack('!I', length_data)[0]
            response = f.read(response_length)

            yield request, response
