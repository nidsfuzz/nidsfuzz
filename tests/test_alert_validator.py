import contextlib
import pathlib
import random
import threading
import time
import unittest
from collections import deque
from pprint import pprint
from queue import Queue

import exrex

from rule import Rule
from sanitization import AlertMonitor
from sanitization.AlertValidator import AlertValidator


class MockAlertEmitter:
    MOCK_RULE = Rule.from_string(
        r'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 ( '
        r'msg:"PROTOCOL-FTP authorized_keys"; '
        r'flow:to_server,established; '
        r'content:"authorized_keys",fast_pattern,nocase; '
        r'metadata:ruleset community; '
        r'service:ftp; '
        r'classtype:suspicious-filename-detect; '
        r'sid:1927; rev:8; )'
    )

    MOCK_CLIENT_IP = "172\\.18\\.0\\.10"
    MOCK_SERVER_IP = "192\\.168\\.0\\.10"

    MOCK_CLIENT_PORT = 10000
    MOCK_SERVER_PORT = 21

    def __init__(self, target_files: list[str], port_window: deque[int], test_packets: Queue[tuple]):
        self.target_files = target_files
        self.port_window = port_window
        self.test_packets = test_packets

        self.emitter_stats: dict[int, list[int]] = {}

        self._active_event = threading.Event()
        self._worker: threading.Thread = None

    def append_alert(self, file_paths: list[str], num_alerts: int, interval: float = 0.1) -> None:
        alert_files = {}
        try:
            with contextlib.ExitStack() as stack:
                for file_path in file_paths:
                    file_handle = stack.enter_context(open(file_path, "a", encoding="utf-8"))
                    alert_files[file_path] = file_handle

                client_port = self.MOCK_CLIENT_PORT
                server_port = self.MOCK_SERVER_PORT

                for _ in range(num_alerts):
                    self._active_event.wait()

                    normal_alert_template = (
                        r'^08/04-09:18:38\.635286 \[\*\*] \[1:1927:8] EXAMPLE \[\*\*] \[Classification: A suspicious filename was detected] \[Priority: 2] \{TCP} '
                        fr'{self.MOCK_CLIENT_IP}:{client_port} -> {self.MOCK_SERVER_IP}:{server_port}')
                    abnormal_alert_template = (
                        r'^08/04-09:18:38\.635286 \[\*\*] \[1:\d{4}:\d{1}] EXAMPLE \[\*\*] \[Classification: A suspicious filename was detected] \[Priority: 2] \{TCP} '
                        fr'{self.MOCK_CLIENT_IP}:{client_port} -> {self.MOCK_SERVER_IP}:{server_port}')

                    self.port_window.append(client_port)
                    self.test_packets.put(([self.MOCK_RULE], (self.MOCK_CLIENT_IP.replace("\\", ""), client_port),
                                           (self.MOCK_SERVER_IP.replace("\\", ""), server_port), [b''], [b'']))

                    match random.randint(a=1, b=2):
                        case 1:
                            self.emitter_stats.setdefault(1, []).append(client_port)
                            alert_line = exrex.getone(regex_string=normal_alert_template)
                            for path, handle in alert_files.items():
                                # logger.debug(f'Writing an alert to: {path}')
                                print(alert_line, file=handle)
                                handle.flush()
                        case 2:
                            self.emitter_stats.setdefault(2, []).append(client_port)
                            alert_lines = [exrex.getone(regex_string=abnormal_alert_template) for _ in
                                           range(len(file_paths))]
                            for (path, handle), line in zip(alert_files.items(), alert_lines):
                                print(line, file=handle)
                                handle.flush()
                        case _:
                            raise RuntimeError(f'Unexpected emitting scenario occurred.')

                    client_port += 1
                    time.sleep(interval)
        except FileNotFoundError as e:
            print(f'File "{file_path}" not found: {e}')

    def resume(self):
        self._active_event.set()

    def pause(self):
        self._active_event.clear()

    def start(self, num_alerts: int = 200):
        files = [pathlib.Path(file_path) for file_path in self.target_files]
        for file in files:
            if file.exists():
                file.unlink()
            file.touch(exist_ok=False)

        self._worker = threading.Thread(target=self.append_alert, args=(self.target_files, num_alerts,))
        self._worker.daemon = True
        self._worker.start()

    def stop(self):
        self._worker.join()


class TestAlertValidator(unittest.TestCase):

    def setUp(self):

        self.target_files = [
            pathlib.Path(__file__).parent / 'alert1.txt',
            pathlib.Path(__file__).parent / 'alert2.txt',
            pathlib.Path(__file__).parent / 'alert3.txt',
        ]

        self.test_packets = Queue()
        self.port_window = deque(maxlen=100)

    def test_main(self):
        # Start the alert emitter
        mock_alert_emitter = MockAlertEmitter(
            [str(file_path) for file_path in self.target_files],
            self.port_window,
            self.test_packets
        )
        mock_alert_emitter.start(num_alerts=200)
        mock_alert_emitter.resume()

        # Start the alert monitor
        alert_files = {str(file_path): deque() for file_path in self.target_files}
        alert_monitor = AlertMonitor(monitored_alerts=alert_files)
        alert_monitor.start()
        alert_monitor.resume()

        # Start the alert validator
        alert_validator = AlertValidator(
            test_bundles=self.test_packets,
            nids_bundles=alert_files,
            port_window=self.port_window,
        )
        try:
            while True:
                print(f'The size of test cases: {self.test_packets.qsize()}')
                print(f'The size of port window: {len(self.port_window)}')
                print(f'The size of alert files: {[len(alert_deque) for alert_deque in alert_files.values()]}')
                time.sleep(1)
                if self.test_packets.qsize() >= 25:
                    mock_alert_emitter.pause()
                    alert_monitor.pause()
                    while self.test_packets.qsize() > 5:
                        for selected_rules, client_addr, server_addr, requests, responses, platform_alerts in alert_validator.validate():
                            pass
                    mock_alert_emitter.resume()
                    alert_monitor.resume()
        except KeyboardInterrupt:
            pass
        finally:
            alert_monitor.stop()
            mock_alert_emitter.stop()
            for selected_rules, client_addr, server_addr, requests, responses, platform_alerts in alert_validator.finalize():
                pass

            time.sleep(1)
            print(
                f'The statistics of the {mock_alert_emitter.__class__.__name__}: normal ({len(mock_alert_emitter.emitter_stats[1])}) abnormal ({len(mock_alert_emitter.emitter_stats[2])})')

    def tearDown(self):
        for file_path in self.target_files:
            if file_path.exists():
                file_path.unlink()
