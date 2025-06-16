import itertools
from typing import Generator

from preprocessing import Rule
from preprocessing.rule_selector.generic_selector import GenericSelector

class PermutationSelector(GenericSelector):

    def select(self) -> Generator[list[Rule], None, None]:
        while True:
            # `permutations()` is a permutation without repetition
            # `product()` is a permutation with repetition, i.e., a Cartesian product
            for perm in itertools.product(self.rule_pool, repeat=self.batch_size):
                yield perm
            if not self.repeatable:
                break


if __name__ == '__main__':
    from pathlib import Path
    from preprocessing.rule_parser.RuleSet import RuleSet
    rule_file = Path(__file__).parent.parent.parent.parent / 'resources' / 'rules' / 'snort3-protocol-other.rules'
    ruleset = RuleSet.from_file(f'{rule_file}')

    selector = PermutationSelector(rule_pool=ruleset, batch_size=2, repeatable=False)
    for rules in selector.select():
        print(f'batch: {[rule.id for rule in rules]}')