import struct
from enum import Enum

from logger import logger
from injection.msg.TuningMessage import TuningMessage


class MessageReceiver:
    class State(Enum):
        WAITING_FOR_HEADER = 1
        WAITING_FOR_BODY = 2

    def __init__(self):
        self.buffer = b''
        self.current_state = self.State.WAITING_FOR_HEADER
        self.current_message_header = {}

    def receive(self, data_chunk: bytes) -> list[TuningMessage]:
        self.buffer += data_chunk
        parsed_messages = []

        while True:
            if self.current_state == self.State.WAITING_FOR_HEADER:
                if len(self.buffer) >= TuningMessage.HEADER_LENGTH:
                    header_bytes = self.buffer[:TuningMessage.HEADER_LENGTH]
                    try:
                        opcode, port, length = TuningMessage.unpack_header(header_bytes)
                        self.current_message_header = {
                            "opcode": opcode,
                            "port": port,
                            "length": length
                        }
                        self.buffer = self.buffer[TuningMessage.HEADER_LENGTH:]
                        self.current_state = self.State.WAITING_FOR_BODY
                        continue
                    except (ValueError, struct.error) as e:
                        logger.error(f"Error parsing message header: {e}")
                        # Parsing failed, possibly corrupted data was received.
                        self.buffer = b''
                        self.current_state = self.State.WAITING_FOR_HEADER
                        return parsed_messages
                else:
                    # Waiting for more data to parse
                    break

            elif self.current_state == self.State.WAITING_FOR_BODY:
                if len(self.buffer) >= self.current_message_header["length"]:
                    body_bytes = self.buffer[:self.current_message_header["length"]]

                    try:
                        full_message_bytes = struct.pack(
                            TuningMessage.HEADER_FORMAT,
                            self.current_message_header["opcode"],
                            self.current_message_header["port"],
                            self.current_message_header["length"],
                        ) + body_bytes

                        message = TuningMessage.from_bytes(full_message_bytes)
                        parsed_messages.append(message)

                        self.buffer = self.buffer[self.current_message_header["length"]:]
                        self.current_state = self.State.WAITING_FOR_HEADER
                        self.current_message_header = {}
                    except (ValueError, struct.error) as e:
                        logger.error(f"Error parsing full message: {e}")
                        self.buffer = b''
                        self.current_state = self.State.WAITING_FOR_HEADER
                        self.current_message_header = {}
                        return parsed_messages
                else:
                    # Waiting for more data to parse
                    break

            else:
                logger.error(f"Unexpected message state: {self.current_state}")
                self.buffer = b''
                self.current_state = self.State.WAITING_FOR_HEADER
                break

        return parsed_messages