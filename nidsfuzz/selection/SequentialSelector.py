from rule import Rule
from selection.GenericSelector import GenericSelector


class SequentialSelector(GenericSelector):

    def reset(self):
        super().reset()

    def select(self) -> tuple[str, list[Rule]]:
        if len(self.current_rule_pool) < self.batch_size:
            self.reset()

        rule_batch = [self.current_rule_pool.pop(0) for _ in range(self.batch_size)]
        self.filtered_rules.setdefault(self.current_service, []).extend(rule_batch)
        return self.current_service, rule_batch

    def filter(self, *rules: Rule):
        pass