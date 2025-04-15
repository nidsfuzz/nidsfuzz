from unittest import TestCase

from commons import utils


class TestCommons(TestCase):

    def test_port_selector(self):
        port_selector = utils.select_port()
        for port in port_selector:
            print(port)
