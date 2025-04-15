
from unittest import TestCase

import logger


class TestLogger(TestCase):

    def test_logger(self):
        logger.trace("A trace message.", test_case="1:8080:1")
        logger.debug("A debug message.", test_case="1:8080:1")
        logger.info("An info message.", test_case="1:8080:1")
        logger.success("A success message.", test_case="1:8080:1")
        logger.warning("A warning message.", test_case="1:8080:1")
        logger.error("An error message.", test_case="1:8080:1")
        logger.critical("A critical message.", test_case="1:8080:1")
