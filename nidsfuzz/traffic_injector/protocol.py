

class EchoMessage:

    def __init__(self, receive: True, reflect: bool, data: bytes = None):
        self.receive = receive
        self.reflect = reflect
        self.data: bytes = data

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"-" if not self.reflect else f"{self.data.hex()}"