import copy
import inspect
import itertools
import random
from typing import Generator

from rule_handler import RuleSet, Rule


class RuleSelector:

    def __init__(self,
                 select_strategy: str,
                 batch_size: int = 1,
                 repeatable: bool = False,
                 only_activated: bool = False):
        if select_strategy not in self.implemented_strategies:
            raise ValueError(f"Strategy must be one of the following: {self.implemented_strategies}")

        self._select_strategy = select_strategy
        self._batch_size = batch_size
        self._repeatable = repeatable
        self._only_activated = only_activated

    @property
    def implemented_strategies(self, prefix='_', suffix='_strategy') -> list[str]:
        strategies = []
        for name, func in inspect.getmembers(RuleSelector, predicate=inspect.isfunction):
            if name.startswith(prefix) and name.endswith('_strategy'):
                strategies.append(name[len(prefix):-len(suffix)])
        return strategies

    def select(self, rule_pool: RuleSet) -> Generator[list[Rule], None, None]:
        func_name = f'_{self._select_strategy}_strategy'
        yield from getattr(self, func_name)(rule_pool)

    def _combine_strategy(self, rule_pool: RuleSet) -> Generator[list[Rule], None, None]:
        if self._only_activated:
            _rule_pool = copy.copy(rule_pool.activated_rules)
        else:
            _rule_pool = copy.copy(rule_pool.rules)

        while True:
            for comb in itertools.combinations(_rule_pool, self._batch_size):
                yield comb
            if not self._repeatable:
                break

    def _permutate_strategy(self, rule_pool: RuleSet, ) -> Generator[list[Rule], None, None]:
        if self._only_activated:
            _rule_pool = copy.copy(rule_pool.activated_rules)
        else:
            _rule_pool = copy.copy(rule_pool.rules)

        while True:
            for comb in itertools.permutations(_rule_pool, self._batch_size):
                yield comb
            if not self._repeatable:
                break

    def _random_strategy(self, rule_pool: RuleSet) -> Generator[list[Rule], None, None]:
        if self._only_activated:
            _rule_pool = copy.copy(rule_pool.activated_rules)
        else:
            _rule_pool = copy.copy(rule_pool.rules)
        while True:
            pool_size = len(_rule_pool)
            # shuffle the rules pool
            random.shuffle(_rule_pool)
            for i in range(0, pool_size, self._batch_size):
                batch = _rule_pool[i: i + self._batch_size]
                if len(batch) < self._batch_size:
                    # Repeat the last element to fill this batch
                    batch.extend([batch[-1]] * (self._batch_size - len(batch)))
                yield batch
            if not self._repeatable:
                break

    def _sequential_strategy(self, rule_pool: RuleSet) -> Generator[list[Rule], None, None]:
        if self._only_activated:
            _rule_pool = copy.copy(rule_pool.activated_rules)
        else:
            _rule_pool = copy.copy(rule_pool.rules)
        while True:
            pool_size = len(_rule_pool)
            for i in range(0, pool_size, self._batch_size):
                batch = _rule_pool[i: i + self._batch_size]
                if len(batch) < self._batch_size:
                    # Repeat the last element to fill this batch
                    batch.extend([batch[-1]] * (self._batch_size - len(batch)))
                yield batch
            if not self._repeatable:
                break