import pathlib
import threading
import time
import unittest
from collections import deque

import exrex

from sanitization import AlertMonitor


def append_alerts(file_path: str, interval: int = 1.0, num_alerts: int = 10):
    """
    Write one alert to the specified file `file_path` every `interval seconds`,
    writing a total of `num_alerts` lines.
    """
    with open(file_path, "a", encoding='utf-8') as f:
        for _ in range(num_alerts):
            line = exrex.getone(regex_string=AlertMonitor.ALERT_PATTERN)
            print(line, file=f)
            f.flush()
            print(f'Writing to {file_path}: \n\t{line}')
            time.sleep(interval)
    print('Finished alert appending.')

class TestAlertMonitor(unittest.TestCase):

    def setUp(self):
        self.file_1 = pathlib.Path(__file__).parent / 'alert1.txt'
        self.file_2 = pathlib.Path(__file__).parent / 'alert2.txt'

        self.snort2_alert_file = pathlib.Path(__file__).parent.parent / 'resources' / 'alerts' / 'snort2.log'
        self.snort3_alert_file = pathlib.Path(__file__).parent.parent / 'resources' / 'alerts' / 'snort3.log'
        self.suricata_alert_file = pathlib.Path(__file__).parent.parent / 'resources' / 'alerts' / 'suricata.log'

    def test_mimic_appending_alerts(self):
        if self.file_1.exists():
            self.file_1.unlink()
        if self.file_2.exists():
            self.file_2.unlink()

        self.file_1.touch(exist_ok=False)
        self.file_2.touch(exist_ok=False)

        file_1_appender = threading.Thread(target=append_alerts, args=(self.file_1,), daemon=True)
        file_2_appender = threading.Thread(target=append_alerts, args=(self.file_2,), daemon=True)
        file_1_appender.start()
        file_2_appender.start()

        file_1_appender.join()
        file_2_appender.join()

    def test_monitor_mimic_alerts(self):
        alert_files = {alert_file: deque() for alert_file in [str(self.file_1), str(self.file_2)]}
        alert_monitor = AlertMonitor(monitored_alerts=alert_files)
        alert_monitor.start()
        alert_monitor.resume()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            alert_monitor.stop()

        self.file_1.unlink()
        self.file_2.unlink()

    def test_monitor_actual_alerts(self):
        alert_files = { alert_file: deque() for alert_file in
                        [str(self.snort2_alert_file), str(self.snort3_alert_file), str(self.suricata_alert_file)]}
        alert_monitor = AlertMonitor(monitored_alerts=alert_files)
        alert_monitor.start()
        alert_monitor.resume()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            alert_monitor.stop()
            print(f'The number of monitored alerts: ')
            print(f'Snort 2: {len(alert_files[str(self.snort2_alert_file)])}')  # 5017
            print(f'Snort 3: {len(alert_files[str(self.snort3_alert_file)])}')  # 8004 - 134 - 2 = 7868
            print(f'Suricata: {len(alert_files[str(self.suricata_alert_file)])}')  # 1740