
from injection import logger
from injection.orch_proto.client import OrchClient, NormClient


class TunableInitiator:

    def __init__(self,
                 host: str,
                 orch_port: int,
                 data_port: int,
                 ):
        self.host = host
        self.echo_port = orch_port
        self.data_port = data_port

        self._orch_channel = OrchClient(self.host, self.echo_port)
        self._data_channel = NormClient(self.host, self.data_port)

    def fuzz(self,
             request: bytes,
             response: bytes,
             orch_sock: tuple[str, int]=None,
             data_sock: tuple[str, int]=None):

        _send = not (request is None or request == b"")
        _receive = not (response is None or response == b"")

        # if both request and response are None, do nothing.
        if not _send and not _receive:
            return

        # establish an orchestration channel with the server
        self._orch_channel.disconnect()
        self._orch_channel.connect(sockname=orch_sock)
        # send an orchestration message to the server
        logger.debug(f"sending data: {response.hex()}", context="echo")
        self._orch_channel.send(
            response,
            receive=_send,
            reflect=_receive
        )

        # establish a data channel with the server
        self._data_channel.disconnect()
        self._data_channel.connect(sockname=data_sock)

        if _send:
            # send a request to the data channel
            logger.debug(f"sending data: {request.hex()}", context="data")
            self._data_channel.send(request)
        else:
            logger.debug(f"no data sent to ({self.host}, {self.data_port})", context="data")

        if _receive:
            _response = self._data_channel.receive()
            # debug usage
            logger.debug(f"received response: {_response.hex()}", context="data")
            logger.debug(f"Is this round of testing successful?: {_response == response}")
        else:
            logger.debug(f"no data received from ({self.host}, {self.data_port})", context="data")
            logger.debug(f"Is this round of testing successful?: True")

    def stop(self):
        if self._data_channel is not None:
            self._data_channel.disconnect()
            self._data_channel = None
        if self._orch_channel is not None:
            self._orch_channel.disconnect()
            self._orch_channel = None

