import random

from logger import logger
from generation.PassThroughMutator import PassThroughSignatureRender, DataChunk, PassThroughMutator
from rule import Pcre, Isdataat, ByteTest, Content, RuleSet, Rule, Option

"""
    This strategy contains two modes for repeating the rule signatures:
        (i) Element-wise repetition that repeats the signatures individually.
        (ii) Block-wise repetition that treats certain options in the same sticky buffer
             as a group and then repeats the group.
"""

class RepetitionSignatureRender(PassThroughSignatureRender):

    def push_content(self, content: Content) -> bool:
        if super().push_content(content):
            return True

        data = content.bytes_matches
        if content['offset'] or content['depth']:
            # increase the offset by the corresponding value to skip repeated options
            start_idx = self.preceding_data_chunk_end_index + int(content['offset'] or 0)
            self.data_chunks.append(DataChunk(start_idx, data))
            self.preceding_data_chunk_end_index = start_idx + len(data)
            return True

        return False

    def push_pcre(self, pcre: Pcre) -> bool:
        return super().push_pcre(pcre)

    def push_isdataat(self, isdataat: Isdataat) -> bool:
        # Repetition usually results in very long data, so there is no need to consider isdataat
        return True

    def push_bytetest(self, bytetest: ByteTest) -> bool:
        return super().push_bytetest(bytetest)


class RepetitionMutator(PassThroughMutator):

    def __init__(self, ruleset: RuleSet,
                 mode: str = 'block-wise',
                 repeat_times: int = 100,
                 min_repeat_times: int = 10,
                 max_repeat_times: int = 1000):
        super().__init__(ruleset)

        if mode.lower() in ['block-wise', 'element-wise']:
            self.mode = mode.lower()
        else:
            logger.error(f'Unknown working mode: {mode}')
            raise ValueError(f'Unknown working mode: {mode}')

        if min_repeat_times > max_repeat_times:
            logger.error(
                f'The minimum repeat times [{min_repeat_times}] must be smaller than the maximum obfuscation times [{max_repeat_times}].')
            raise ValueError(
                f'The minimum repeat times [{min_repeat_times}] must be smaller than the maximum obfuscation times [{max_repeat_times}].')

        if not min_repeat_times <= repeat_times <= max_repeat_times:
            logger.error(
                f'The repeat times should be in the range [{min_repeat_times}, {max_repeat_times}], but got [{repeat_times}].')
            raise ValueError(
                f'The repeat times should be in the range [{min_repeat_times}, {max_repeat_times}], but got [{repeat_times}].')

        self.repeat_times = repeat_times
        self.min_repeat_times = min_repeat_times
        self.max_repeat_times = max_repeat_times

        logger.info(f'Repetition mutator initialized.')

    def mutate_signatures(self, *rules: Rule) -> dict[str, list[Option]]:
        signatures = {}
        for buffer, options in rules[0].signature.items():
            options = self.eliminate_redundant_options(options)
            # The repeat_times is randomly selected, and the probability follows a Gaussian distribution.
            repeat_times = int(random.triangular(low=self.min_repeat_times, high=self.max_repeat_times,
                                                 mode=self.repeat_times))
            logger.debug(f'Repeat times: {repeat_times}')
            match self.mode.lower():
                case 'block-wise':
                    repeated_options = options * repeat_times
                    signatures.setdefault(buffer, []).extend(repeated_options)
                case 'element-wise':
                    repeated_options = []
                    for option in options:
                        repeated_options.extend([option] * repeat_times)
                    signatures.setdefault(buffer, []).extend(repeated_options)
                case _:
                    logger.error(f'Unknown working mode: {self.mode}')
                    raise ValueError(f'Unknown working mode: {self.mode}')
        return signatures

    def is_valid(self, *rules: Rule, proto: str) -> bool:
        if len(rules) != 1:
            logger.warning(f'Expected 1 rule, got {len(rules)}')
            return False
        return True

    def render_signatures(self, sticky_buffer, proto) -> PassThroughSignatureRender:
        return RepetitionSignatureRender(sticky_buffer, proto)
