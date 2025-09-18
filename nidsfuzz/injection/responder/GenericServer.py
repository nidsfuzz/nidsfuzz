import abc
import socket
import select

from logger import logger


class GenericServer(abc.ABC):

    def __init__(self, listen_addr: tuple[str, int]):
        self.listen_addr = listen_addr

        self.max_socket_num = 1000
        self.local_socket = None
        self.client_sockets = {}
        self.all_sockets: list[socket.socket] = []

    def bind(self):
        try:
            self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.local_socket.setblocking(False)
            self.local_socket.bind(self.listen_addr)
            self.local_socket.listen(self.max_socket_num)
            self.all_sockets.append(self.local_socket)
            logger.info(f"Server listening on {self.listen_addr}")
        except socket.error as e:
            logger.error(e)
            raise RuntimeError(f"Failed to bind socket to {self.listen_addr}.")

    def listen(self):
        while self.all_sockets:
            readable, _, _ = select.select(self.all_sockets, [], [], 0.1)

            for sock in readable:
                if sock == self.local_socket:
                    client_socket, client_addr = self.local_socket.accept()
                    client_socket.setblocking(False)
                    self.client_sockets[client_socket.fileno()] = (client_socket, client_addr)
                    self.all_sockets.append(client_socket)
                    self.client_connected_callback(client_socket, client_addr)
                else:
                    try:
                        data = sock.recv(4096)
                        if data:
                            self.data_received_callback(sock, data)
                        else:
                            # No data means the client has gracefully closed the connection
                            self.teardown(sock)
                    except ConnectionResetError:
                        # Client forcibly closed the connection
                        self.teardown(sock)
                    except BlockingIOError:
                        # This can happen if setblocking(False) is active and there's no data yet.
                        # It's generally fine to ignore in this select loop context.
                        pass
                    except Exception as e:
                        logger.error(e)
                        self.teardown(sock)

    def teardown(self, client_socket: socket.socket):
        if client_socket in self.all_sockets:
            self.all_sockets.remove(client_socket)

        if client_socket.fileno() in self.client_sockets:
            del self.client_sockets[client_socket.fileno()]

        client_socket.close()
        self.client_disconnected_callback(client_socket)

    def stop(self):
        for sock in self.all_sockets:
            if sock.fileno() in self.client_sockets:
                self.teardown(sock)

        if self.local_socket:
            self.local_socket.shutdown(socket.SHUT_RDWR)
            self.local_socket.close()
            self.local_socket = None

        logger.info(f"Server stopped.")

    def send(self, client_socket: socket.socket, data: bytes):
        try:
            client_socket.sendall(data)
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error(f"Error sending to client {self.client_sockets[client_socket.fileno()][1]}: {e}.")
            self.teardown(client_socket)
        except Exception as e:
            logger.error(f'Unexpected error sending data: {e}')


    @abc.abstractmethod
    def client_connected_callback(self, client_socket, client_addr):
        pass

    @abc.abstractmethod
    def data_received_callback(self, client_socket, data):
        pass

    @abc.abstractmethod
    def client_disconnected_callback(self, client_socket):
        pass

