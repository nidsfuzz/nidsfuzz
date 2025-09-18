import asyncio
import pathlib
import unittest

from Replayer import Replayer
from injection import TunableResponder


class TestReplaying(unittest.TestCase):

    def setUp(self):
        self.anchor = pathlib.Path(__file__).parent.parent / 'tests'
        self.tuning_port = 23456
        self.tuned_port = 34567

    def test_tunable_responder(self):
        tunable_server = TunableResponder(
            tuning_listen_addr=("0.0.0.0", self.tuning_port),
            tuned_listen_addr=("0.0.0.0", self.tuned_port),
        )
        asyncio.run(tunable_server.start())

    def test_replayer(self):
        replayer = Replayer(
            initiator_addr="127.0.0.1",
            responder_addr="127.0.0.1",
            tuning_port=self.tuning_port,
            tuned_port=self.tuned_port,
            input_dir=str(self.anchor),
        )

        replayer.start()
