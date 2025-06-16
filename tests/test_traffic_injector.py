from unittest import TestCase

from injection import TunableResponder, TunableInitiator


class TestTrafficInjector(TestCase):

    def test_responder(self):
        server = TunableResponder(
            host="0.0.0.0",
            orch_port=34567,
            data_port=8080
        )

        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()

    def test_initiator(self):
        client = TunableInitiator(
            host="127.0.0.1",
            orch_port=34567,
            data_port=8080)

        request = b'hello server!'
        response = b'hello client!'

        client.fuzz(
            request=request,
            response=response,
        )

        if client is not None:
            client.stop()