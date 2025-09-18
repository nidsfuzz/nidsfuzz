from collections import defaultdict
from typing import Any


class AccumulationAnalyzer:

    def __init__(self, threshold: int = 1):
        if threshold < 1:
            raise ValueError(f'The threshold is at least greater than 1')

        # The name "item map" is inspired by the "bit map" concept in the fuzzing domain
        self.item_map: dict[Any, int] = defaultdict(int)
        self.threshold = threshold

        # print(f'Successfully initialized the accumulation analyzer with threshold: {threshold}')

    def update(self, *items: Any) -> list[Any]:
        burst_items = []
        for item in items:
            self.item_map[item] += 1
            if self.item_map[item] >= self.threshold:
                # print(f'Item {item} exceeds threshold {self.threshold}')
                burst_items.append(item)
                self.item_map[item] = 0
        return burst_items


if __name__ == '__main__':

    test_cases = ['1:1:1', "1:1:1, 2:2:2", "3:3:3, 4:4:4", "4:4:4, 5:5:5"]

    analyzer = AccumulationAnalyzer(threshold=2)

    for test_case in test_cases:
        print(analyzer.update(*test_case.split(", ")))





