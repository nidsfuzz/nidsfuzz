import asyncio
from asyncio import CancelledError

from logger import logger
from injection.responder.AsyncGenericServer import AsyncGenericServer
from injection.msg.MessageReceiver import MessageReceiver
from injection.msg.OpcodeEnum import OpcodeEnum
from injection.msg.TuningMessage import TuningMessage


class MessageBroker:

    def __init__(self):
        self.messages: dict[tuple[str, int], TuningMessage] = {}

    async def publish_message(self, conn_addr: tuple[str, int], message: TuningMessage, timeout: int = 1):
        start_time = asyncio.get_event_loop().time()

        while conn_addr in self.messages:
            elapsed_time = asyncio.get_event_loop().time() - start_time
            if elapsed_time > timeout:
                logger.error(f"Timeout reached. Message '{conn_addr}' exists for too long without consumption.")
                raise TimeoutError(f"Timeout reached. Message '{conn_addr}' exists for too long without consumption.")

            logger.debug(f"Message '{conn_addr}' exists, waiting for a service to consume it.")
            await asyncio.sleep(0.1)

        self.messages[conn_addr] = message

    async def consume_message(self, conn_addr: tuple[str, int], timeout: int = 1) -> TuningMessage:
        start_time = asyncio.get_event_loop().time()

        while conn_addr not in self.messages:
            elapsed_time = asyncio.get_event_loop().time() - start_time
            if elapsed_time > timeout:
                logger.error(f"Timeout reached. Message '{conn_addr}' does not exist.")
                raise TimeoutError(f"Timeout reached. Message '{conn_addr}' does not exist.")

            logger.debug(f"Message '{conn_addr}' does not exist, waiting for a service to publish it.")
            await asyncio.sleep(0.1)

        message = self.messages[conn_addr]
        del self.messages[conn_addr]
        return message


message_broker = MessageBroker()

################################################################################
################################################################################


class TuningService(AsyncGenericServer):

    def __init__(self, name: str, listen_addr: tuple[str, int]):
        super().__init__(name, listen_addr)

        self.message_receivers = {}

    async def client_connected_callback(self, writer: asyncio.StreamWriter, client_addr: tuple[str, int]):
        self.message_receivers[writer] = MessageReceiver()
        logger.debug(f"{self.name}: Accepted a client connection from {client_addr}")

    async def data_received_callback(self, writer: asyncio.StreamWriter, data: bytes):
        client_addr = writer.get_extra_info("peername")
        logger.debug(f"{self.name}: Received data received from {client_addr}: {data}")
        receiver = self.message_receivers.get(writer)
        parsed_messages = receiver.receive(data)
        for msg in parsed_messages:
            await message_broker.publish_message(conn_addr=(client_addr[0], msg.port), message=msg)

    async def client_disconnected_callback(self, writer: asyncio.StreamWriter):
        logger.debug(f"{self.name}: Disconnected from {writer.get_extra_info('peername')}")


class TunedService(AsyncGenericServer):

    async def client_connected_callback(self, writer: asyncio.StreamWriter, client_addr: tuple[str, int]):
        logger.debug(f"{self.name}: Accepted a client connection from {client_addr}")

    async def data_received_callback(self, writer: asyncio.StreamWriter, data: bytes):
        client_addr = writer.get_extra_info("peername")
        logger.debug(f"{self.name}: Received data received from {client_addr}: {data}")
        message = await message_broker.consume_message(conn_addr=client_addr)
        opcode = OpcodeEnum.from_int(message.opcode)
        if opcode == OpcodeEnum.NO_OP:
            pass
        elif opcode == OpcodeEnum.ECHO_WAIT:
            await self.send(writer=writer, data=message.data)
            logger.debug(f'{self.name}: Sent data to {client_addr}: {message.data}')

        else:
            logger.error(f"{self.name}: Unsupported opcode: {opcode}")

    async def client_disconnected_callback(self, writer: asyncio.StreamWriter):
        logger.debug(f"{self.name}: Disconnected from {writer.get_extra_info('peername')}")

################################################################################
################################################################################


class TunableResponder:

    def __init__(self,
                 tuning_listen_addr: tuple[str, int],
                 tuned_listen_addr: tuple[str, int],):

        self.tuning_service = TuningService("Tuning Service", tuning_listen_addr)
        self.tuned_service = TunedService("Tuned Service", tuned_listen_addr)


    async def start(self):
        try:
            await asyncio.gather(self.tuning_service.start(), self.tuned_service.start())
        except (CancelledError, KeyboardInterrupt):
            pass

    async def stop(self):
        await asyncio.gather(self.tuning_service.stop(), self.tuned_service.stop())



