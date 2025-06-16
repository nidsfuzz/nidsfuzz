import itertools
from typing import Generator

from preprocessing import Rule
from preprocessing.rule_selector.generic_selector import GenericSelector

class CombinationSelector(GenericSelector):

    def select(self) -> Generator[list[Rule], None, None]:
        while True:
            # Allow repeated combinations (mathematically referred to as "repeated combinations")
            for comb in itertools.combinations_with_replacement(self.rule_pool, self.batch_size):
                yield comb
            if not self.repeatable:
                break


if __name__ == '__main__':
    from pathlib import Path
    from preprocessing.rule_parser.RuleSet import RuleSet
    rule_file = Path(__file__).parent.parent.parent.parent / 'resources' / 'rules' / 'snort3-protocol-other.rules'
    ruleset = RuleSet.from_file(f'{rule_file}')

    selector = CombinationSelector(rule_pool=ruleset, batch_size=2, repeatable=False)
    for rules in selector.select():
        print(f'batch: {[rule.id for rule in rules]}')