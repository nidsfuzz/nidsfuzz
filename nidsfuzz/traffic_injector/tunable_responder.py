import sys

import logger
from . import EchoService, DataService


class TunableResponder:
    """
    Example Usage:
    --------
    >>> host = "0.0.0.0"
    >>> echo_port = 5556
    >>> data_port = 8080
    >>> responder = TunableResponder(host, echo_port, data_port)
    >>> try:
    >>>     responder.start()
    >>> except KeyboardInterrupt:
    >>>     responder.stop()
    """

    def __init__(self,
                 host: str,
                 echo_port: int,
                 data_port: int,
                 ):
        self._running = True

        self.echo_addr = (host, echo_port)
        self.data_addr = (host, data_port)

        try:
            self.echo_service = EchoService(*self.echo_addr)
            self.data_service = DataService(*self.data_addr)
        except RuntimeError as e:
            logger.error(str(e))
            sys.exit(1)

    def start(self):
        logger.debug("tunable responder starting...")

        while self._running:
            # The client of the echo service disconnects after each request and reconnects for the next one.
            # Therefore, the server needs to close any pre-existing client connection after handling each request
            # and then accept a new client connection.
            self.echo_service.disconnect()
            self.echo_service.connect()

            logger.debug(f"accepted connection from {self.echo_service.client_addr}", service="echo")

            # receive and parse the echo message, continue on socket disconnect.
            try:
                echo_message = self.echo_service.receive()
                logger.debug(f"received data: {echo_message}", service="echo")
            except Exception as e:
                logger.error(str(e), service='echo')
                continue

            # accept a connection of the data service
            self.data_service.disconnect()
            self.data_service.connect()
            logger.debug(f"accepted connection from {self.data_service.client_addr}", service="data")

            # receive and ignore the fuzz data, continue on socket disconnect.
            if echo_message.receive:
                try:
                    fuzz_data = self.data_service.receive()
                    logger.debug(f"received data: {fuzz_data.hex()}", service="data")
                except Exception as e:
                    logger.error(str(e), service='data')
                    continue
            else:
                logger.debug(f"no data received from {self.data_service.client_addr}", service="data")

            # reflect echo message to the fuzz client, continue on socket disconnect.
            if echo_message.reflect:
                try:
                    self.data_service.send(echo_message.data)
                    logger.debug(f"send data: {echo_message.data.hex()}", service="data")
                except Exception as e:
                    logger.error(str(e), service='data')
                    continue
            else:
                logger.debug(f"no data sent to {self.data_service.client_addr}", service="data")

    def stop(self):
        logger.debug("tunable responder stopping...")
        self._running = False
        try:
            self.echo_service.release()
        except Exception as e:
            pass
        try:
            self.data_service.release()
        except Exception as e:
            pass
