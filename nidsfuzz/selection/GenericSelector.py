import abc

from rule import RuleSet, Rule, Proto


class GenericSelector(abc.ABC):

    def __init__(self,
                 ruleset: RuleSet,
                 batch_size: int,
                 batch_num: int,
                 proto: str = None,
                 ):
        if batch_size < 1:
            raise ValueError(f"batch_size must be greater than 1, but got {batch_size}")
        if batch_num < 1:
            raise ValueError(f"batch_num must be greater than 1, but got {batch_num}")

        if proto is not None and proto.lower() not in Proto.all():
            raise ValueError(f"proto must be one of {Proto.all()}, but got {proto}")

        self.ruleset: list[Rule] = ruleset.activated_rules
        self.batch_size = batch_size
        self.batch_num = batch_num
        self.proto = proto.lower() if proto is not None else None

        #################################
        self.rule_pools: dict[str, list[Rule]] = self._preprocess()
        self.filtered_rules: dict[str, list[Rule]] = {}

        if proto is None:
            self.current_service: str = next(iter(self.rule_pools))
            self.current_rule_pool: list[Rule] = self.rule_pools[self.current_service]
        else:
            self.current_service: str = proto
            self.current_rule_pool: list[Rule] = self.rule_pools[proto]

        self.is_finished = False

        #################################
        self.count = 0

    def __iter__(self):
        return self

    def __next__(self) -> tuple[str, list[Rule]]:
        if self.is_finished:
            raise StopIteration

        # Stop the selection if the expected number of rule batches has already been selected.
        if self.count >= self.batch_num:
            self.is_finished = True
            raise StopIteration

        proto, rules = self.select()
        self.count += 1

        return proto, rules

    def _preprocess(self) -> dict[str, list[Rule]]:
        """
        Group the rule pool based on service to ensure the selected rules share the same application protocol.
        :return:
            A dictionary mapping service names to their applied rules.
        """
        result = {}
        for rule in self.ruleset:
            services = [s.lower() for s in rule.service.split(",") if s.lower() in Proto.all()]
            for service in services:
                result.setdefault(service, []).append(rule)
        for service, rules in list(result.items()):
            if len(rules) < self.batch_size:
                del result[service]
        if len(result) == 0:
            raise ValueError(f'The input ruleset does not satisfy the expected batch size: {self.batch_size}')
        return result

    def switch(self):
        """
        If the current rule pool runs out, this method switches to the next rule pool or creates a new one.
        """
        if self.proto is not None:
            self.rule_pools = self._preprocess()
            self.filtered_rules.pop(self.proto, None)
            self.is_finished = False
            self.current_service = self.proto
            self.current_rule_pool = self.rule_pools[self.proto]
        else:
            if len(self.rule_pools) > 1:
                self.rule_pools.pop(self.current_service, None)
            else:
                self.rule_pools = self._preprocess()
            self.is_finished = False
            self.current_service: str = next(iter(self.rule_pools))
            self.current_rule_pool = self.rule_pools[self.current_service]

    @abc.abstractmethod
    def reset(self):
        self.switch()

    @abc.abstractmethod
    def select(self) -> tuple[str, list[Rule]]:
        pass

    @abc.abstractmethod
    def filter(self, *rules: Rule):
        try:
            for rule in rules:
                self.current_rule_pool.remove(rule)
                self.filtered_rules.setdefault(self.current_service, []).append(rule)
        except ValueError:
            from logger import logger
            logger.error(f'Current service: {self.current_service}')
            logger.error(f'Current rule pool: {[rule.id for rule in self.current_rule_pool]}')
            logger.error(f'Filtered rules: {[rule.id for rule in rules]}')
            # import sys
            # sys.exit(1)


