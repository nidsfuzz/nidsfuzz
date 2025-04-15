
from unittest import TestCase

from traffic_injector.tunable_responder import TunableResponder


class TestTunableResponder(TestCase):
    def test_tunable_responder(self):
        server = TunableResponder(
            host="0.0.0.0",
            echo_port=34567,
            data_port=8080
        )

        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()


