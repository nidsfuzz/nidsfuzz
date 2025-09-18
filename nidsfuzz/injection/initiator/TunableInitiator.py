import time

from logger import logger
from injection.initiator.GenericClient import GenericClient
from injection.msg.OpcodeEnum import OpcodeEnum
from injection.msg.TuningMessage import TuningMessage


class TunableInitiator:

    def __init__(self,
                 host: str,
                 tuning_port: int,
                 tuned_port: int):
        self.remote_tuning_addr = (host, tuning_port)
        self.tuning_client = GenericClient(self.remote_tuning_addr)
        self.local_tuning_addr = None

        self.remote_tuned_addr = (host, tuned_port)
        self.tuned_client = GenericClient(self.remote_tuned_addr)
        self.local_tuned_addr = None

    def connect(self, local_tuning_addr: tuple[str, int] = None, local_tuned_addr: tuple[str, int] = None):
        logger.debug(f'Connecting to responder with address: {local_tuned_addr[0]}:{local_tuned_addr[1]}')
        self.local_tuning_addr = local_tuning_addr
        self.tuning_client.connect(local_addr=local_tuning_addr)

        self.local_tuned_addr = local_tuned_addr
        self.tuned_client.connect(local_addr=local_tuned_addr)

    def teardown(self):
        if self.tuning_client.is_connected:
            self.tuning_client.teardown()
            self.local_tuning_addr = None
        if self.tuned_client.is_connected:
            self.tuned_client.teardown()
            self.local_tuned_addr = None

    @property
    def is_connected(self) -> bool:
        return self.tuned_client.is_connected

    def inject(self, request: bytes, response: bytes):
        if request is None or response is None:
            raise RuntimeError('Request or response cannot be None')

        if request != b"" and response != b"":
            opcode = OpcodeEnum.ECHO_WAIT
        elif request != b"" and response == b"":
            opcode = OpcodeEnum.NO_OP
        elif request == b"" and response != b"":
            opcode = OpcodeEnum.ECHO_NODELAY
        else:
            return

        if not self.tuned_client.is_connected:
            raise RuntimeError('The initiator should connect with the responder before injecting traffic.')

        port = self.local_tuned_addr[1]

        tuning_message = TuningMessage(opcode=opcode.value, port=port, data=response)

        self.tuning_client.send(data=tuning_message.pack())

        if opcode == OpcodeEnum.ECHO_WAIT:
            self.tuned_client.send(data=request)
            received_response = self.tuned_client.receive()
            # assert response == received_response
        elif opcode == OpcodeEnum.NO_OP:
            self.tuned_client.send(data=request)
            time.sleep(0.01)
        elif opcode == OpcodeEnum.ECHO_NODELAY:
            received_response = self.tuned_client.receive()
            # assert response == received_response

