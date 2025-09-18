from enum import IntEnum

from logger import logger


class OpcodeEnum(IntEnum):
    NO_OP = 0x00
    ECHO_NODELAY = 0x01
    ECHO_WAIT = 0x02

    def __str__(self):
        return f"{self.name} (0x{self.value:04X})"

    @classmethod
    def from_int(cls, value: int) -> "OpcodeEnum":
        try:
            return cls(value)
        except ValueError:
            logger.error(f'"{value}" is not a valid opcode.')
            raise ValueError(f'"{value}" is not a valid opcode.')