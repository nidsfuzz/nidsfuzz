from typing import Generator

from .mutate_strategy.rule_combine_strategy import RuleCombineStrategy
from .mutate_strategy.rule_obfuscate_strategy import RuleObfuscateStrategy
from .mutate_strategy.rule_random_strategy import RuleRandomStrategy
from .mutate_strategy.rule_repeat_strategy import RuleRepeatStrategy
from rule_handler import Rule


class RuleMutator:

    STRATEGY = {
        "combine": RuleCombineStrategy(),
        "obfuscate": RuleObfuscateStrategy(),
        "repeat": RuleRepeatStrategy(),
        "random": RuleRandomStrategy()
    }

    def __init__(self, mutate_strategy: str):
        if self.STRATEGY.get(mutate_strategy, None) is None:
            raise ValueError("Invalid mutate strategy")

        self.mutate_strategy = self.STRATEGY[mutate_strategy]

    def mutate(self,  rules: list[Rule]) -> Generator[tuple[bytes, bytes], None, None]:
        yield from self.mutate_strategy.mutate(rules)


