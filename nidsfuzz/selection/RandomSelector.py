import random

from rule import RuleSet, Rule
from selection.GenericSelector import GenericSelector


class RandomSelector(GenericSelector):

    def reset(self):
        super().reset()

    def select(self) -> tuple[str, list[Rule]]:
        """
        Selects a rule batch by:
        1. Randomly choosing one pool from `self.rule_pools`.
        2. Randomly sampling `batch_size` rules from the selected pool.
        :return:
            Str: The chosen protocol.
            List[Rule]: A list of selected rules.
        """
        if self.proto is None:
            self.current_service = random.choice(list(self.rule_pools))
            self.current_rule_pool = self.rule_pools[self.current_service]

        if len(self.current_rule_pool) < self.batch_size:
            self.reset()

        rule_batch = random.sample(self.current_rule_pool, self.batch_size)
        return self.current_service, rule_batch

    def filter(self, *rules: Rule):
        super().filter(*rules)