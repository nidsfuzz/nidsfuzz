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


def save_alert_discrepancies(file_path: str, selected_rules: str, aligned_alerts: dict[str, list[tuple]]):
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(selected_rules + '\n')
        for alert_file, alert_list in aligned_alerts.items():
            triggered_alerts = ', '.join([e[0] for e in alert_list])  # Only record the ID of the fired rule
            f.write(alert_file + ': ' + triggered_alerts + '\n')
        f.write('\n')

def save_test_packets(file_path: str, request: bytes, response: bytes):
    with open(file_path, 'ab') as f:
        f.write(struct.pack('!I', len(request)))
        f.write(request)
        f.write(struct.pack('!I', len(response)))
        f.write(response)

def load_alert_discrepancies(file_path: str) -> Generator[list[str], None, None]:
    with open(file_path, 'r') as f:
        data_unit = []
        for line in f:
            line = line.strip()
            if line == "":
                yield data_unit
                data_unit.clear()
            else:
                data_unit.append(line)

def load_test_packets(file_path: str) -> Generator[tuple[bytes, bytes], None, None]:
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
