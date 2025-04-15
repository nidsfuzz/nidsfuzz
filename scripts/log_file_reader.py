import re

snort3_log_pattern = re.compile(
    (r'^.*? \[\*\*] \[(?P<rule_id>\d+:\d+:\d+)] .*? \[\*\*] \[Classification.*?] \[Priority.*?] \{.*?} '
     r'(?P<src_ip>\d+\.\d+\.\d+.\d+):(?P<src_port>\d+) -> (?P<dst_ip>\d+\.\d+\.\d+.\d+):('
     r'?P<dst_port>\d+)')
)

suricata_log_pattern = re.compile(
    (r'^.*? \[\*\*] \[(?P<rule_id>\d+:\d+:\d+)] .*? \[\*\*] \[Classification.*?] \[Priority.*?] \{.*?} '
     r'(?P<src_ip>\d+\.\d+\.\d+.\d+):(?P<src_port>\d+) -> (?P<dst_ip>\d+\.\d+\.\d+.\d+):('
     r'?P<dst_port>\d+)')
)

pattern = {
    'snort3': snort3_log_pattern,
    'suricata': suricata_log_pattern
}


def read_log(file_path: str, nids: str):
    patt = pattern.get(nids, None)
    if patt is None:
        raise ValueError(nids)

    alert_num = 0

    with open(file_path, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip()
            match = re.match(patt, line)
            if not match:
                continue
            else:
                print(f'Rule ID: {match.group("rule_id")}')
                alert_num += 1
    return alert_num


def test():
    snort3_log_str = r'09/12-21:23:49.803656 [**] [1:8058:11] "BROWSER-FIREFOX Mozilla javascript navigator object access" [**] [Classification: Attempted User Privilege Gain] [Priority: 1] {TCP} 192.168.0.10:80 -> 172.18.0.10:41074'
    suricata_log_str = r'09/12/2024-21:23:49.804363  [**] [1:8058:11] BROWSER-FIREFOX Mozilla javascript navigator object access [**] [Classification: Attempted User Privilege Gain] [Priority: 1] {TCP} 192.168.0.10:80 -> 172.18.0.10:41074'

    snort3_match = re.match(snort3_log_pattern, snort3_log_str)

    if snort3_match:
        print(f'Timestamp: {snort3_match.group("timestamp")}')
        print(f'Rule ID: {snort3_match.group("rule_id")}')
        print(f'Source: {snort3_match.group("src_ip")}:{snort3_match.group("src_port")}')
        print(f'Destination: {snort3_match.group("dst_ip")}:{snort3_match.group("dst_port")}')

    suricata_match = re.match(suricata_log_pattern, suricata_log_str)
    if suricata_match:
        print(f'Timestamp: {suricata_match.group("timestamp")}')
        print(f'Rule ID: {suricata_match.group("rule_id")}')
        print(f'Source: {suricata_match.group("src_ip")}:{suricata_match.group("src_port")}')
        print(f'Destination: {suricata_match.group("dst_ip")}:{suricata_match.group("dst_port")}')


if __name__ == "__main__":
    nids = 'suricata'
    log_file = f'{nids}.log'
    alert_num = read_log(log_file, nids)
    print(f'alert_num: {alert_num}')

    # Snort3 alert number: 44919
    # Suricata alert number: 45222
