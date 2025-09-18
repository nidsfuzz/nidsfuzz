import abc


class GenericStringObfuscation(abc.ABC):

    @abc.abstractmethod
    def obfuscate(self, origin: str, obfuscate_times: int = 1) -> str:
        pass