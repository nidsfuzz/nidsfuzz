import itertools

from rule import Rule, RuleSet
from selection.GenericSelector import GenericSelector


class CombinationSelector(GenericSelector):

    def __init__(self, ruleset: RuleSet, batch_size: int, batch_num: int, proto: str = None,):
        if batch_size < 2:
            raise ValueError(f"batch_size must be greater than 2, but got {batch_size}")

        super().__init__(ruleset, batch_size, batch_num, proto)

        self.current_product_iter = itertools.product(self.current_rule_pool, repeat=self.batch_size)

    def reset(self):
        super().reset()
        self.current_product_iter = itertools.product(self.current_rule_pool, repeat=self.batch_size)

    def select(self) -> tuple[str, list[Rule]]:
        while True:
            try:
                combination = next(self.current_product_iter)
                for rule in combination:
                    if rule in self.filtered_rules.get(self.current_service, []):
                        break
                else:
                    return self.current_service, list(combination)
            except StopIteration:
                self.reset()

    def filter(self, *rules: Rule):
        self.filtered_rules.setdefault(self.current_service, []).extend(rules)




