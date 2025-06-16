import abc
from typing import Generator

from preprocessing import Rule


class GenericStrategy(abc.ABC):

    # The default protocol is HTTP
    def __init__(self, proto: str = 'http'):
        self.proto = proto.upper()

    @abc.abstractmethod
    def mutate(self, rules: list[Rule]) -> Generator[tuple[bytes, bytes], None, None]:
        pass