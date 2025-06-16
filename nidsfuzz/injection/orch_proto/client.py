import abc
import pickle
import socket
import struct
import time

from injection.orch_proto.orch_msg import OrchMessage


class GenericClient(abc.ABC):

    def __init__(self, host, port):
        self._server_addr = (host, port)
        self._server_sock = None
        self._retry = 0

        # Pack two integers (1, 0) into a binary structure for the SO_LINGER socket option.
        # 1 enables the SO_LINGER option, and 0 specifies that the socket should close immediately
        # without waiting for unsent data to be transmitted.
        self.NOLINGER = struct.pack("ii", 0, 0)  # 0,0 is the default behavior

    def connect(self, sockname: tuple[str, int]=None):
        # connect to the server, timeout on failure.
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(3.0)

        # specify the local ip and port of the client
        if sockname is not None:
            self._server_sock.bind(sockname)

        try:
            self._server_sock.connect(self._server_addr)
        except socket.error as e:
            if self._retry != 5:
                self._retry += 1
                time.sleep(5)
                self.connect()
            else:
                raise RuntimeError(f"unable to connect to server {self._server_addr}.")

        # disable timeouts and lingering.
        self._server_sock.settimeout(None)
        # self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.NOLINGER)

    def disconnect(self):
        """Ensure the socket is torn down."""
        if self._server_sock is not None:
            self._server_sock.close()
            self._server_sock = None

    @abc.abstractmethod
    def receive(self):
        pass

    @abc.abstractmethod
    def send(self, data, *args, **kwargs):
        pass


class OrchClient(GenericClient):

    def __init__(self, host, port):
        super().__init__(host, port)

    def receive(self):
        """Reflect client typically does not need to receive any data from the server."""
        try:
            length = struct.unpack("<L", self._server_sock.recv(4))[0]
        except Exception:
            return

        try:
            received = b""
            while length:
                chunk = self._server_sock.recv(length)
                received += chunk
                length -= len(chunk)
        except socket.error as e:
            raise RuntimeError(f"unable to receive data from server {self._server_addr}.")

    def send(self, data, *args, **kwargs):
        _echo_msg = None

        _reflect = kwargs.get("reflect", False)
        _receive = kwargs.get("receive", True)
        if data is None or data == b"":
            _echo_msg = pickle.dumps(OrchMessage(receive=_receive, reflect=_reflect), protocol=2)
        else:
            _echo_msg = pickle.dumps(OrchMessage(receive=_receive, reflect=True, data=data), protocol=2)

        try:
            self._server_sock.send(struct.pack("<L", len(_echo_msg)))
            self._server_sock.send(_echo_msg)
        except socket.error as e:
            raise RuntimeError(f"unable to send data to server {self._server_addr}.")


class NormClient(GenericClient):

    def __init__(self, host, port):
        super().__init__(host, port)

    def receive(self) -> bytes:
        try:
            chunk = self._server_sock.recv(4096)
        except Exception:
            raise RuntimeError(f"client connection {self._server_sock} severed during receiving.")
        return chunk

    def send(self, data, *args, **kwargs):
        try:
            self._server_sock.send(data)
        except Exception:
            raise RuntimeError(f"client connection {self._server_sock} severed during sending.")