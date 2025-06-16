import abc
import copy
from typing import Generator

from preprocessing import RuleSet, Rule


class GenericSelector(abc.ABC):

    def __init__(self,
                 rule_pool: RuleSet,
                 batch_size: int = 1,
                 repeatable: bool = False):
        # Select ONLY from the activated rules
        self.rule_pool: list[Rule] = copy.copy(rule_pool.activated_rules)
        self.batch_size = batch_size
        self.repeatable = repeatable

    @abc.abstractmethod
    def select(self) -> Generator[list[Rule], None, None]:
        pass