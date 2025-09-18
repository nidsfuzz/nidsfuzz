import socket
from collections import deque


class PortAllocator:

    def __init__(self,
                 memory_span: int = 1000, ):
        self.memory: deque[int] = deque(maxlen=memory_span)

    @property
    def memory_span(self) -> int | None:
        return self.memory.maxlen

    def _find_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    def allocate(self, memorize: bool = False) -> int:
        allocated_port = None
        while allocated_port is None or allocated_port in self.memory:
            allocated_port = self._find_free_port()

        if memorize:
            self.memory.append(allocated_port)
        return allocated_port

    def in_memory(self, port: int, start: int = None, stop: int = None) -> int | None:
        try:
            start = start if start is not None else 0
            stop = stop if stop is not None else self.memory.maxlen
            return self.memory.index(port, start, stop)
        except ValueError:
            return None


if __name__ == '__main__':
    port_allocator = PortAllocator()

    print(f'The memory span is: {port_allocator.memory_span}')

    allocated_port = port_allocator.allocate(memorize=True)
    print(f'allocate a port and memorize it: {allocated_port}')
    print(f'allocate a port and do not memory it: {port_allocator.allocate()}')
    print(f'display the memorized ports: {port_allocator.memory}')

    _ = port_allocator.allocate(memorize=True)
    _ = port_allocator.allocate(memorize=True)
    allocated_port = port_allocator.allocate(memorize=True)
    print(f'allocate many ports...')
    print(f'display the memorized ports: {port_allocator.memory}')
    print(f'the index of the allocated port {allocated_port} is: {port_allocator.in_memory(allocated_port, start=2)}')
