from collections import defaultdict

from adaptation import logger

class AccumulationAnalyzer:

    def __init__(self, threshold: int = 1):
        if threshold < 1:
            raise ValueError(f'The threshold is at least greater than 1')

        # The name "rule map" is inspired by the "bit map" concept in the fuzzing domain
        self.rule_map: dict[str, int] = defaultdict(int)
        self.rules_to_be_filtered: set[str] = set()
        self.threshold = threshold

        logger.info(f'Successfully initialized the accumulation analyzer with threshold: {threshold}')

    def update_accumulation(self, rules: str):
        # An example of input rules: "1:30120:1, 1:21545:2"
        rules = rules.split(', ')

        for rule in rules:
            self.rule_map[rule] += 1
            if self.rule_map[rule] >= self.threshold:
                logger.success(f'Rule {rule} requires further investigation')
                self.rules_to_be_filtered.add(rule)

    def validate_rules_for_testing(self, rules: str) -> bool:
        # An example of input rules: "1:30120:1, 1:21545:2"
        rules = rules.split(', ')

        for rule in rules:
            # If the rule has been filtered, it shouldn't be tested again.
            if rule in self.rules_to_be_filtered:
                return False
        return True


if __name__ == '__main__':

    test_cases = ['1:1:1', "1:1:1, 2:2:2", "3:3:3, 4:4:4", "4:4:4, 5:5:5"]

    analyzer = AccumulationAnalyzer(threshold=1)

    for test_case in test_cases:
        analyzer.update_accumulation(test_case)

    print('break point')





