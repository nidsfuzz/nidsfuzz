import abc
import asyncio
from asyncio import CancelledError

from logger import logger


class AsyncGenericServer(abc.ABC):

    def __init__(self, name: str, listen_addr: tuple[str, int]):
        self.name = name
        self.listen_addr = listen_addr
        self.server_socket: asyncio.Server = None
        self.client_sockets: dict[asyncio.StreamWriter, tuple[str, int]] = {}

    async def start(self):
        try:
            logger.info(f"{self.name}: Starting the server listening on {self.listen_addr}")
            self.server_socket = await asyncio.start_server(
                client_connected_cb=self._listen,
                host=self.listen_addr[0],
                port=self.listen_addr[1]
            )
            await self.server_socket.serve_forever()
        except (CancelledError, KeyboardInterrupt):
            logger.info(f"{self.name}: Server interrupted by user.")
            pass
        except Exception as e:
            logger.critical(f"{self.name}: Failed to start server: {e}")
            raise
        finally:
            await self.stop()

    async def stop(self):
        if self.server_socket:
            self.server_socket.close()
            await self.server_socket.wait_closed()
            logger.info(f"{self.name}: Server gracefully stopped: {self.listen_addr}")

        for writer in list(self.client_sockets.keys()):
            await self._teardown(writer)

    async def _listen(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr: tuple[str, int] = writer.get_extra_info('peername')
        self.client_sockets[writer] = client_addr

        await self.client_connected_callback(writer, client_addr)

        try:
            while True:
                data = await reader.read(4096)
                if data:
                    await self.data_received_callback(writer, data)
                else:
                    # Client gracefully closed the connection
                    logger.debug(f"{self.name}: No more data received from {client_addr}.")
                    break
        except ConnectionResetError as e:
            logger.error(f"{self.name}: Client {client_addr} forcibly disconnected.")
        except asyncio.IncompleteReadError as e:
            logger.error(f"{self.name}: Client {client_addr} disconnected unexpectedly during reading.")
        except Exception as e:
            logger.error(f'{self.name}: Error handling client {client_addr}: {e}')
        finally:
            await self._teardown(writer)

    async def _teardown(self, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info('peername')
        if writer in self.client_sockets:
            del self.client_sockets[writer]
            writer.close()
            await writer.wait_closed()
            asyncio.create_task(self.client_disconnected_callback(writer))
        else:
            logger.warning(f"{self.name}: Client {client_addr} is not included in the maintained client_sockets.")

    async def send(self, writer: asyncio.StreamWriter, data: bytes):
        client_addr: tuple[str, int] = writer.get_extra_info('peername')
        try:
            writer.write(data)
            await writer.drain()
        except ConnectionResetError as e:
            logger.warning(f"{self.name}: Failed to send to {client_addr}: {e}")
            await self._teardown(writer)
        except BrokenPipeError as e:
            logger.warning(f"{self.name}: Failed to send to {client_addr}: {e}")
            await self._teardown(writer)
        except Exception as e:
            logger.error(f'{self.name}: Unexpected error sending to {client_addr}: {e}')
            await self._teardown(writer)

    @abc.abstractmethod
    async def client_connected_callback(self, writer: asyncio.StreamWriter, client_addr: tuple[str, int]):
        pass

    @abc.abstractmethod
    async def data_received_callback(self, writer: asyncio.StreamWriter, data: bytes):
        pass

    @abc.abstractmethod
    async def client_disconnected_callback(self, writer: asyncio.StreamWriter):
        pass