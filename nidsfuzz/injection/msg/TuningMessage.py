import struct

from logger import logger


class TuningMessage:
    # Tunable Bilateral Traffic Injection Protocol
    # 2 bytes (opcode) + 2 bytes (port) + 4 bytes (length)
    HEADER_LENGTH = 8
    HEADER_FORMAT = "!HHL"

    def __init__(self, opcode: int, port: int, data: bytes = b''):
        self.opcode: int = opcode
        self.port: int = port
        self.data: bytes = data
        self.length = len(data)

    def pack(self) -> bytes:
        header = struct.pack(self.HEADER_FORMAT, self.opcode, self.port, self.length)
        return header + self.data

    @classmethod
    def unpack_header(cls, header_bytes: bytes) -> tuple[int, int, int]:
        if len(header_bytes) != cls.HEADER_LENGTH:
            raise ValueError(f"Header bytes must be exactly {cls.HEADER_LENGTH} bytes long, but got {len(header_bytes)}")

        try:
            opcode, port, length = struct.unpack(cls.HEADER_FORMAT, header_bytes)
            return opcode, port, length
        except struct.error as e:
            logger.error(f"Failed to unpack header: {e}")
            raise struct.error(f"Failed to unpack header: {e}")

    @classmethod
    def from_bytes(cls, message_bytes: bytes) -> 'TuningMessage':
        if len(message_bytes) < cls.HEADER_LENGTH:
            raise ValueError(f'Message bytes too short to contain a header ({len(message_bytes)} < {cls.HEADER_LENGTH} bytes).')

        header_bytes = message_bytes[:cls.HEADER_LENGTH]
        opcode, port, length = cls.unpack_header(header_bytes)

        body_bytes = message_bytes[cls.HEADER_LENGTH:]
        if len(body_bytes) < length:
            raise ValueError(f'Data length mismatch: header indicates {length} bytes, but received {len(body_bytes)} bytes.')

        return cls(opcode, port, body_bytes)

    def __repr__(self):
        return (f'{self.__class__.__name__}(opcode={self.opcode}, port={self.port}, length={self.length}, '
                f'data={self.data!r})')

    def __str__(self):
        return (f'Opcde: {self.opcode}\n'
                f'Port: {self.port}\n'
                f'Length: {self.length}\n'
                f'Data: {self.data.decode(errors="replace")}')

