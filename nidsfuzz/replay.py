import random

import psutil

import logger
from traffic_injector.tunable_initiator import TunableInitiator
from commons import utils


def select_ports(start=1024, end=65535) -> tuple[int, int]:
    occupied_ports = {conn.laddr.port for conn in psutil.net_connections() if conn.laddr}
    while True:
        echo_port, data_port = random.sample(range(start, end), 2)
        if data_port not in occupied_ports and echo_port not in occupied_ports:
            return echo_port, data_port


class Replay:

    def __init__(self,
                 local_ip: str,
                 remote_ip: str,
                 echo_port: int,
                 data_port: int,
                 traffic: str
                 ):
        self.local_ip = local_ip
        self.tunable_initiator = TunableInitiator(remote_ip, echo_port, data_port)
        self.traffic = traffic

    def replay(self):
        case_id = 0
        for request, response in utils.read_traffic(self.traffic):
            case_id += 1
            local_echo_port, local_data_port = select_ports()
            echo_sock = (self.local_ip, local_echo_port)
            data_sock = (self.local_ip, local_data_port)
            logger.debug(f"replay case: {case_id}")
            logger.debug(f"local echo port: {local_echo_port}    local data port: {local_data_port}")
            self.tunable_initiator.fuzz(request=request, response=response, echo_sock=echo_sock, data_sock=data_sock)
