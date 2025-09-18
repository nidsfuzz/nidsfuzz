import asyncio
import unittest

from injection import TunableResponder, TunableInitiator


class TestBilateralInjector(unittest.TestCase):

    def setUp(self):
        pass

    def test_tunable_responder(self):
        responder = TunableResponder(
            tuning_listen_addr=("0.0.0.0", 34567),
            tuned_listen_addr=("0.0.0.0", 8080)
        )
        asyncio.run(responder.start())

    def test_tunable_initiator(self):
        initiator = TunableInitiator(
            host="127.0.0.1",
            tuning_port=34567,
            tuned_port=8080,
        )
        initiator.connect(('127.0.0.1', 55241), ('127.0.0.1', 55342))
        initiator.inject(request=b'hello server!', response=b'hello client!')
        initiator.inject(request=b'hello server!', response=b'')
        initiator.inject(request=b'hello server!', response=b'hello client!')
        initiator.teardown()