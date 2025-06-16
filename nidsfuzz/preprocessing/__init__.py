from logger import logger_manager
logger = logger_manager.setup_logger("preprocessing")


from preprocessing.rule_parser.Rule import Rule
from preprocessing.rule_parser.RuleSet import RuleSet

from preprocessing.rule_selector.sequential_selector import SequentialSelector
from preprocessing.rule_selector.random_selector import RandomSelector
from preprocessing.rule_selector.combination_selector import CombinationSelector
from preprocessing.rule_selector.permutation_selector import PermutationSelector

def load_selector(algorithm: str,
                  rule_pool: RuleSet,
                  batch_size: int = 1,
                  repeatable: bool = False
                  ):
    rule_selector = None
    match algorithm.lower():
        case "sequential" | "sequential_selection":
            rule_selector = SequentialSelector(
                rule_pool=rule_pool,
                batch_size=batch_size,
                repeatable=repeatable
            ).select()
        case "random" | "random_selection":
            rule_selector = RandomSelector(
                rule_pool=rule_pool,
                batch_size=batch_size,
                repeatable=repeatable
            ).select()
        case "permutation" | "permutation_selection":
            rule_selector = PermutationSelector(
                rule_pool=rule_pool,
                batch_size=batch_size,
                repeatable=repeatable
            ).select()
        case "combination" | "combination_selection":
            rule_selector = CombinationSelector(
                rule_pool=rule_pool,
                batch_size=batch_size,
                repeatable=repeatable
            ).select()
        case _:
            logger.error(f'Unknown selection algorithm: {algorithm}')

    logger.info(f'Successfully applied selection algorithm: {algorithm}')
    return rule_selector