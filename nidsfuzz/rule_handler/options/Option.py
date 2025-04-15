import abc

class Option(dict, metaclass=abc.ABCMeta):

    @classmethod
    @abc.abstractmethod
    def from_string(cls, raw: str):
        pass

    @abc.abstractmethod
    def __str__(self):
        pass

    def __repr__(self):
        return self.__str__()