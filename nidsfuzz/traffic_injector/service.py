import abc
import errno
import pickle
import socket
import struct

import select

from . import EchoMessage


class Service(abc.ABC):

    def __init__(self, host, port):
        self._server_addr = (host, port)
        self._server_sock = None
        self._client_sock = None
        self._client_addr = None
        self._bind()

    @property
    def server_addr(self):
        return self._server_addr

    @property
    def client_addr(self):
        return self._client_addr

    def _bind(self):
        """Create and bind the server socket."""
        try:
            # create a socket and bind to the specified port.
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.settimeout(None)
            self._server_sock.bind(self._server_addr)
            self._server_sock.listen(1)
        except socket.error:
            raise RuntimeError(f"Failed to bind socket to {self._server_addr}.")

    def connect(self):
        """Accept a client socket connection."""
        while True:
            readable, writeable, errored = select.select([self._server_sock], [], [], 0.1)
            if len(readable) > 0:
                assert readable[0] == self._server_sock
                (self._client_sock, self._client_addr) = self._server_sock.accept()
                break

    def disconnect(self):
        """Ensure the client socket is torn down."""
        if self._client_sock is not None:
            try:
                # shutdown the read and write channel of socket
                self._client_sock.shutdown(socket.SHUT_RDWR)
            except socket.error as e:
                if e.errno in [errno.ENOTCONN, errno.EBADF]:
                    pass
                else:
                    raise
            self._client_sock.close()

    def release(self):
        """Ensure that the sockets on both sides are closed."""
        self.disconnect()

        try:
            self._server_sock.shutdown(socket.SHUT_RDWR)
        except socket.error as e:
            if e.errno == errno.ENOTCONN:
                pass
            else:
                raise
        self._server_sock.close()

    def is_connecting(self):
        if self._client_sock is None:
            return False
        readable, writable, errored = select.select([self._client_sock], [], [self._client_sock], 0)
        if errored:
            return False  # If an error occurs, the connection is unavailable.
        return True

    @abc.abstractmethod
    def receive(self):
        """Receive and parse data from the client socket."""
        pass

    @abc.abstractmethod
    def send(self, data, *args, **kwargs):
        """Wrap and send data to the client socket."""
        pass


class EchoService(Service):

    def __init__(self, host, port):
        super().__init__(host, port)

    def receive(self) -> EchoMessage:
        try:
            length = struct.unpack("<L", self._client_sock.recv(4))[0]
            received = b""
            while length:
                chunk = self._client_sock.recv(length)
                received += chunk
                length -= len(chunk)
        except Exception:
            raise RuntimeError(f"client connection {self._client_addr} severed during receiving.")
        res = pickle.loads(received)
        return res

    def send(self, data, *args, **kwargs):
        """Reflect service does not need to send any data to the client."""
        pass


class DataService(Service):

    def __init__(self, host, port):
        super().__init__(host, port)

    def receive(self) -> bytes:
        try:
            chunk = self._client_sock.recv(4096)
        except Exception:
            raise RuntimeError(f"client connection {self._client_addr} severed during receiving.")
        return chunk

    def send(self, data: bytes, *args, **kwargs):
        try:
            self._client_sock.send(data)
        except Exception:
            raise RuntimeError(f"client connection {self._client_addr} severed during sending.")
