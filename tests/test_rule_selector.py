import pathlib
import unittest

from rule import RuleSet
from selection import RandomSelector, SequentialSelector, CombinationSelector


class TestRuleSelector(unittest.TestCase):

    def setUp(self):
        self.rule_file = pathlib.Path(__file__).parent.parent / 'resources' / 'rules' / 'snort3-community.rules'
        self.ruleset = RuleSet.from_file(str(self.rule_file))

    def test_random_selector(self):
        selector = RandomSelector(
            ruleset=self.ruleset,
            batch_num=1000,
            batch_size=2,
        )

        print('Start selecting:')

        for proto, rules in selector:
            print(f'proto: {proto}')
            print(f'rules: {[rule.id for rule in rules]}')

        print(f'The number of selections is: {selector.count}')

    def test_sequential_selector(self):
        selector = SequentialSelector(
            ruleset=self.ruleset,
            batch_num=1000,
            batch_size=1,
        )

        print('Start selecting:')

        for proto, rules in selector:
            print(f'proto: {proto}')
            print(f'rules: {[rule.id for rule in rules]}')

        print(f'The number of selections is: {selector.count}')

    def test_combination_selector(self):
        selector = CombinationSelector(
            ruleset=self.ruleset,
            batch_num=1000,
            batch_size=2,
        )

        print('Start selecting:')

        for proto, rules in selector:
            print(f'proto: {proto}')
            print(f'rules: {[rule.id for rule in rules]}')

        print(f'The number of selections is: {selector.count}')