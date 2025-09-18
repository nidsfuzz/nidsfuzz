from collections import Counter
from typing import Callable

from logger import logger


"""
    This class provides a decorator to automatically register oracle methods.
    Specifically, each oracle method receives two arguments:
    (i) Input Rules: the rules used for generating test packets. An example is: 
        [ "1:59600:1" ]
    (ii) Output Rules: the rules fired by the test packets on various NIDS platforms. For example: 
        [   [ "1:59600:1", "1:59600:1" ]
            [ "1:38282:1", "1:59600:1" ],
            [ "1:59600:1" ],                ]
"""


class TestOracle:

    def __init__(self):
        self.oracle_methods: list[Callable[..., bool]] = []

    def register(self, func):
        logger.info(f'--- Registering oracle method: {func.__name__} ---')
        self.oracle_methods.append(func)
        return func

    def run(self, *args, **kwargs) -> tuple[bool, dict[str, bool]]:
        details = {}
        for oracle_method in self.oracle_methods:
            is_normal = bool(oracle_method(*args, **kwargs))
            details[oracle_method.__name__] = is_normal
            if not is_normal:
                logger.debug(f'Oracle "{oracle_method.__name__}" triggered.')
        all_passed = all(details.values())
        return all_passed, details

test_oracle = TestOracle()


##############################################

@test_oracle.register
def rule_orthogonality_oracle(
        input_rules: list[str],
        output_rules: list[list[str]],
) -> bool:
    """
    We assume that a packet derived from seed rules should either trigger or not trigger only that specific
    seed rules, and should not be related to any other rules. Therefore, if a NIDS platform generates additional
    alerts, this is considered abnormal behavior.
    """
    for platform_rules in output_rules:
        if any(platform_rule not in input_rules for platform_rule in platform_rules):
            logger.success(f'\tFound overlapping rules.')
            return False
    return True

@test_oracle.register
def nids_consistency_oracle(
        input_rules: list[str],
        output_rules: list[list[str]],
) -> bool:
    """
    We assume that a packet should trigger the same alerts across all NIDS platforms. If a NIDS platform generates
    different alerts, this is considered abnormal behavior.
    """
    counters = [Counter(platform_rules) for platform_rules in output_rules]
    equal = all(counter == counters[0] for counter in counters)
    if not equal:
        logger.success(f'\tFound inconsistent rule enforcement.')
        return False
    return True