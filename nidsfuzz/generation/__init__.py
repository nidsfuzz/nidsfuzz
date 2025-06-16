# Note that it's necessary to first import logger before importing strategies
from logger import logger_manager
logger = logger_manager.setup_logger("generation")

from .rule_mutator.repetition_strategy import RepetitionStrategy
from .rule_mutator.obfuscation_strategy import ObfuscationStrategy
from .rule_mutator.random_strategy import RandomStrategy
from .rule_mutator.blending_strategy import BlendingStrategy


def load_mutator(strategy: str):
    rule_mutator = None
    match strategy.lower():
        case "pass" | "pass-through" | "blending":
            rule_mutator = BlendingStrategy()
        case "repetition":
            rule_mutator = RepetitionStrategy()
        case "obfuscation":
            rule_mutator = ObfuscationStrategy()
        case "random":
            rule_mutator = RandomStrategy()
        case _:
            logger.error(f'Unknown mutation strategy: {strategy}')

    logger.info(f'Successfully applied mutation strategy: {strategy}')
    return rule_mutator
