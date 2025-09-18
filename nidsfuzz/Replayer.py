import time

from logger import logger
from Fuzzer import Fuzzer
from commons import PortAllocator
from injection import TunableInitiator


class Replayer:

    def __init__(self,
                 initiator_addr: str,
                 responder_addr: str,
                 tuning_port: int,
                 tuned_port: int,
                 input_dir: str,):

        self.initiator_addr = initiator_addr
        self.responder_addr = responder_addr
        self.tuning_port = tuning_port
        self.tuned_port = tuned_port
        self.input_dir = input_dir

        self.tunable_initiator = TunableInitiator(
            host=responder_addr,
            tuning_port=tuning_port,
            tuned_port=tuned_port,
        )
        self.port_allocator = PortAllocator()

    def start(self):
        replay_num = 0

        discrepancies = Fuzzer.load_discrepancies(file_anchor=self.input_dir)
        packets = Fuzzer.load_packets(file_anchor=self.input_dir)

        while True:
            try:
                seed_rules, platform_alerts = next(discrepancies)
                requests, responses = next(packets)

                replay_num += 1
                logger.info(f'Replaying: {", ".join(seed_rules)}')

                tuned_port = self.port_allocator.allocate(memorize=True)
                tuning_port = self.port_allocator.allocate(memorize=False)

                self.tunable_initiator.connect(
                    (self.initiator_addr, tuning_port),
                    (self.initiator_addr, tuned_port))
                for request, response in zip(requests, responses):
                    self.tunable_initiator.inject(request=request, response=response)
                self.tunable_initiator.teardown()

                time.sleep(0.1)
            except StopIteration:
                logger.info(f'There is no records need to replay, already replayed: {replay_num}')
                break