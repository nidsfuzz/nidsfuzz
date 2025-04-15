from unittest import TestCase

from rule_selector import RuleSelector
from rule_handler import RuleSet


class TestRuleSelector(TestCase):

    def test_rule_selector(self):
        import os
        rule_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "resources",
            "snortrules-snapshot-31470",
            "rules",
            "snort3-protocol-other.rules"
        )
        ruleset = RuleSet.from_file(rule_file)
        print(ruleset)

        selector = RuleSelector(
            select_strategy='combine',
            batch_size=2,
            repeatable=False,
            only_activated=False,
        )

        for rule_batch in selector.select(ruleset):
            print([rule.id for rule in rule_batch])

