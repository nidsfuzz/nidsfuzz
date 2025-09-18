import socket
import time

from logger import logger


class GenericClient:

    def __init__(self, server_addr: tuple[str, int]):
        self.server_addr = server_addr

        self.max_retry_num = 5
        self.socket = None
        self.connected = False

    def connect(self, local_addr: tuple[str, int]=None):

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.socket.settimeout(3.0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable port reuse
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 0, 0))

        if local_addr is not None:
            self.socket.bind(local_addr)

        retry_num = 0
        while retry_num < self.max_retry_num:
            try:
                self.socket.connect(self.server_addr)
                self.connected = True
                return
            except socket.error as e:
                retry_num += 1
                if retry_num <= self.max_retry_num:
                    time.sleep(1)
                else:
                    logger.error(f"Failed to connect to {self.server_addr}: {e}")
                    raise RuntimeError(f"Unable to connect to server: {self.server_addr}")

    def teardown(self):
        if self.socket is not None:
            self.socket.close()
            self.connected = False
            self.socket = None

    @property
    def is_connected(self) -> bool:
        return self.connected

    def send(self, data: bytes):
        try:
            self.socket.send(data)
        except Exception as e:
            logger.error(f"Failed to send data to {self.server_addr}: {e}")
            raise RuntimeError(f"client connection {self.server_addr} severed during sending.")

    def receive(self) -> bytes:
        try:
            chunk = self.socket.recv(4096)
        except Exception as e:
            logger.error(f'Failed to receive data from {self.server_addr}: {e}')
            raise RuntimeError(f"client connection {self.server_addr} severed during receiving.")
        return chunk