from enum import Enum, auto


class ProtoType(Enum):
    TEXT = 0
    BIN = 1


class Proto(Enum):
    HTTP = ('http', 80, ProtoType.TEXT)
    SIP = ('sip', 5060, ProtoType.TEXT)
    FTP = ('ftp', 21, ProtoType.TEXT)
    IMAP = ('imap', 143, ProtoType.TEXT)
    POP = ('pop', 110, ProtoType.TEXT)

    DNS = ('dns', 53, ProtoType.BIN)
    TELNET = ('telnet', 23, ProtoType.BIN)


    def __init__(self, name: str, port: int, type: ProtoType):
        if not isinstance(type, ProtoType):
            raise ValueError(f'Invalid protocol type: {type}')

        self._value = name
        self._type = type
        self._port = port

    @property
    def type(self) -> ProtoType:
        return self._type

    @property
    def value(self) -> str:
        return self._value

    @property
    def port(self) -> int:
        return self._port

    @classmethod
    def lookup(cls, name: str) -> 'Proto':
        for member in cls:
            if member.value == name.lower():
                return member
        raise ValueError(f'Unknown protocol: {name}')

    @classmethod
    def all(cls) -> set[str]:
        all_proto = set()
        for member in cls:
            all_proto.add(member.value)
        return all_proto

if __name__ == '__main__':
    proto = Proto.HTTP
    print(f'The name of proto: {proto.value}')

    print(f'all protocols: {Proto.all()}')