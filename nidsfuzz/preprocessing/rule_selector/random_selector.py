import random
from typing import Generator

from preprocessing import Rule
from preprocessing.rule_selector.generic_selector import GenericSelector

class RandomSelector(GenericSelector):

    def select(self) -> Generator[list[Rule], None, None]:
        while True:
            pool_size = len(self.rule_pool)
            # shuffle the rule pool
            random.shuffle(self.rule_pool)
            for i in range(0, pool_size, self.batch_size):
                # If the slice exceeds the list length,
                # Python will truncate it to the end of the list.
                batch = self.rule_pool[i: i + self.batch_size]
                if len(batch) < self.batch_size:
                    # Repeat the last element to fill this batch
                    batch.extend(
                        [batch[-1]] * (self.batch_size - len(batch))
                    )
                yield batch
            if not self.repeatable:
                break


if __name__ == '__main__':
    from pathlib import Path
    from preprocessing.rule_parser.RuleSet import RuleSet
    rule_file = Path(__file__).parent.parent.parent.parent / 'resources' / 'rules' / 'snort3-protocol-other.rules'
    ruleset = RuleSet.from_file(f'{rule_file}')

    selector = RandomSelector(rule_pool=ruleset, batch_size=2, repeatable=False)
    for rules in selector.select():
        print(f'batch: {[rule.id for rule in rules]}')