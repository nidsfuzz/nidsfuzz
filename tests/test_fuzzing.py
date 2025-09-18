import asyncio
import unittest
from pathlib import Path

from Fuzzer import Fuzzer
from injection import TunableResponder


class TestFuzzing(unittest.TestCase):

    def setUp(self):
        self.rule_file = Path(__file__).parent.parent / 'resources' / 'rules' / 'snort3-protocol-dns.rules'
        self.alert_file = Path(__file__).parent / 'alert_file.txt'
        self.tuning_port = 23456
        self.tuned_port = 34567

    def test_tunable_server(self):
        tunable_server = TunableResponder(
            tuning_listen_addr=("0.0.0.0", self.tuning_port),
            tuned_listen_addr=("0.0.0.0", self.tuned_port),
        )
        asyncio.run(tunable_server.start())

    def test_fuzzer(self):
        if self.alert_file.exists():
            self.alert_file.unlink()
        self.alert_file.touch(exist_ok=False)

        fuzzer = Fuzzer(
            initiator_addr="127.0.0.1",
            responder_addr="127.0.0.1",
            tuning_port=self.tuning_port,
            tuned_port=self.tuned_port,
            output_dir='output',
            proto='dns',
        ).setup_selection(
            rule_files=[str(self.rule_file)],
            algorithm='sequential',
            batch_size=1,
            batch_num=1000,
        ).setup_generation(
            algorithm='pass-through',
        ).setup_sanitization(
            alert_files=[str(self.alert_file)],
        ).setup_adaptation(
            threshold=1,
        )

        fuzzer.start()

        try:
            fuzzer.join()
        except KeyboardInterrupt:
            fuzzer.stop()
            fuzzer.join()
            if self.alert_file.exists():
                self.alert_file.unlink()

    def tearDown(self):
        if self.alert_file.exists():
            self.alert_file.unlink()