from unittest import TestCase
from pathlib import Path

from preprocessing import RuleSet, load_selector



class TestRuleSelector(TestCase):

    def test_load_selector(self):
        algorithm = "sequential"
        rule_pool = Path(__file__).parent.parent / "resources" / "rules" / "snort3-browser-chrome.rules"
        batch_size = 1
        repeatable = False

        rule_selector = load_selector(
            algorithm=algorithm,
            rule_pool=RuleSet.from_file(f'{rule_pool}'),
            batch_size=batch_size,
            repeatable=repeatable
        )

        rule_batch = next(rule_selector)
        print(f'The first selected rule batch: {rule_batch}')

        for rule_batch in rule_selector:
            print(f'{[rule.id for rule in rule_batch]}')