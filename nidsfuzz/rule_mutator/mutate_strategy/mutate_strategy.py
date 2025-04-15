import abc
from typing import Generator

from rule_handler import Rule


class MutateStrategy(abc.ABC):

    def __init__(self, proto: str = 'http'):
        self._proto = proto.upper()

    def set_proto(self, proto: str):
        self._proto = proto.upper()

    @abc.abstractmethod
    def mutate(self, rules: list[Rule]) -> Generator[tuple[bytes, bytes], None, None]:
        pass
