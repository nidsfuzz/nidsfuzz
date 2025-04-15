from . import EchoClient, DataClient
import logger


class TunableInitiator:

    def __init__(self,
                 host: str,
                 echo_port: int,
                 data_port: int,
                 ):
        self.host = host
        self.echo_port = echo_port
        self.data_port = data_port

        self._echo_channel = EchoClient(self.host, self.echo_port)
        self._data_channel = DataClient(self.host, self.data_port)

    def fuzz(self,
             request: bytes,
             response: bytes,
             echo_sock: tuple[str, int]=None,
             data_sock: tuple[str, int]=None):

        _send = not (request is None or request == b"")
        _receive = not (response is None or response == b"")

        # if both request and response are None, do nothing.
        if not _send and not _receive:
            return

        # establish an echo connection to the server
        self._echo_channel.disconnect()
        self._echo_channel.connect(sockname=echo_sock)
        # send echo message to the server
        logger.debug(f"sending data: {response.hex()}", context="echo")
        self._echo_channel.send(
            response,
            receive=_send,
            reflect=_receive
        )

        # establish a data connection to the server
        self._data_channel.disconnect()
        self._data_channel.connect(sockname=data_sock)

        if _send:
            # send request to the fuzz channel
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
        if self._echo_channel is not None:
            self._echo_channel.disconnect()
            self._echo_channel = None

