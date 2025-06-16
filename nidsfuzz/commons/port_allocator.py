import psutil
import random

class PortAllocator:

    def __init__(self,
                 start: int = 1024,
                 end: int = 65535,
                 port_window_size: int = 25):
        self.start = start
        self.end = end
        self.port_window = list()  # The history of used ports
        self.port_window_size = port_window_size

    def allocate_ports(self, batch_size: int = 2) -> tuple:
        occupied_ports = {conn.laddr.port for conn in psutil.net_connections() if conn.laddr}
        while True:
            allocated_ports = random.sample(range(self.start, self.end), k=batch_size)
            if any(port in occupied_ports for port in allocated_ports):
                print(f'ports: {allocated_ports} are already in use, trying again...')

            self.port_window.append(allocated_ports[0])  # The first port is used for data service
            if len(self.port_window) > self.port_window_size:
                del self.port_window[0]
            return allocated_ports


if __name__ == '__main__':
    port_allocator = PortAllocator(port_window_size=2)
    for i in range(10):
        data_port, orch_port = port_allocator.allocate_ports()
        print(f'data: {data_port}, orchestration: {orch_port}')
        print(f'port window: {port_allocator.port_window}')
        print("===== break point =====")
