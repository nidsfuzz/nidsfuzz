import random
import sys
from pathlib import Path
from platform import system

import psutil

from commons import load_alert_discrepancies, load_test_packets
from injection import TunableInitiator


from logger import logger_manager
logger = logger_manager.setup_logger("replay")


def allocate_ports(start=1024, end=65535) -> tuple[int, int]:
    occupied_ports = {conn.laddr.port for conn in psutil.net_connections() if conn.laddr}
    while True:
        data_port, orch_port = random.sample(range(start, end), 2)
        if data_port not in occupied_ports and orch_port not in occupied_ports:
            return data_port, orch_port


class Replayer:

    def __init__(self,
                 initiator_ip: str,
                 responder_ip: str,
                 orch_port: int,
                 data_port: int,
                 replay_dir: str
                 ):
        self.initiator_ip = initiator_ip
        self.tunable_initiator = TunableInitiator(responder_ip, orch_port, data_port)
        self.test_packets_file = Path(replay_dir) / "packets.bin"
        self.alert_discrepancies_file = Path(replay_dir) / "discrepancies.txt"

        if not self.test_packets_file.exists():
            logger.error(f'No such file: {self.test_packets_file}')
            sys.exit(-1)

        if not self.alert_discrepancies_file.exists():
            logger.error(f'No such file: {self.alert_discrepancies_file}')
            sys.exit(-1)

    def replay(self):
        case_id = 0

        test_packets = load_test_packets(file_path=f'{self.test_packets_file}')
        alert_discrepancies = load_alert_discrepancies(file_path=f'{self.alert_discrepancies_file}')

        while True:
            try:
                request, response = next(test_packets)
                alert_discrepancy = next(alert_discrepancies)
            except StopIteration:
                break

            case_id += 1
            logger.debug(f"replay case: {case_id}")
            logger.debug(f"{alert_discrepancy}")

            data_port, orch_port = allocate_ports()
            orch_sock = (self.initiator_ip, orch_port)
            data_sock = (self.initiator_ip, data_port)
            self.tunable_initiator.fuzz(request=request, response=response, orch_sock=orch_sock, data_sock=data_sock)