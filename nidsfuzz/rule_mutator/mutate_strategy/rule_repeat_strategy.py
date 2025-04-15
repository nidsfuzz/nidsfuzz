import abc
import random
from typing import Generator

import logger
from rule_handler.options import *
from rule_mutator.mutate_strategy.mutate_strategy import MutateStrategy
from rule_mutator.http_constructor.packet_constructor import PacketConstructor
from rule_mutator.http_constructor.buffer_constructor import BufferConstructor, codec
from rule_handler import Rule


class RuleRepeatStrategy(MutateStrategy):

    def __init__(self, min_loop_time: int = 100, max_loop_time: int = 300, proto: str = 'http'):
        super().__init__(proto=proto)
        self.min_loop_time = min_loop_time
        # MaxLoopTime specified by user to limit the maximum times of repetition
        self.max_loop_time = max_loop_time

    def mutate(self, rules: list[Rule]) -> Generator[tuple[bytes, bytes], None, None]:
        """
        There are two modes for repeating the signatures, namely one-by-one repetition
        that repeats the signatures individually and signature group repetition that
        treats certain signatures in the same field as a group and then repeats the group.
        """
        if len(rules) != 1:
            raise ValueError(
                f'[{self.__class__.__name__}]: Rule list must have exactly 1 element, but received  {len(rules)}')

        repeat_time = random.randint(self.min_loop_time, self.max_loop_time)

        # one-by-one repetition
        yield from self._one_by_one_repetition(rules[0], repeat_time=repeat_time)
        # signature group repetition
        yield from self._signature_group_repetition(rules[0], repeat_time=repeat_time)

    def _one_by_one_repetition(self, rule: Rule, repeat_time) -> Generator[tuple[bytes, bytes], None, None]:
        logger.debug(f'Rule [{rule.id}]: starting one by one repetition with repetition time [{repeat_time}]')

        buffers = []
        rule_signature = iter(rule.signature.items())
        last_option = None
        for buffer_name, options in rule_signature:
            next_buffer = next(rule_signature, None)
            if next_buffer is None:
                last_option = options[-1]
                buffers.append(OneByOneRepetition(buffer_name, repeat_time, options, has_rule_last_option=True))
            else:
                buffers.append(OneByOneRepetition(buffer_name, repeat_time, options))

        (incomplete_req, incomplete_res), (complete_req, complete_res) = self._generate(buffers, last_option)

        yield incomplete_req, incomplete_res
        yield complete_req, complete_res

    def _signature_group_repetition(self, rule: Rule, repeat_time) -> Generator[tuple[bytes, bytes], None, None]:
        logger.debug(f'Rule [{rule.id}]: starting signature group repetition with repetition time [{repeat_time}]')

        buffers = []
        rule_signature = iter(rule.signature.items())
        last_option = None
        for buffer_name, options in rule_signature:
            next_buffer = next(rule_signature, None)
            if next_buffer is None:
                last_option = options[-1]
                buffers.append(SignatureGroupRepetition(buffer_name, repeat_time, options, has_rule_last_option=True))
            else:
                buffers.append(SignatureGroupRepetition(buffer_name, repeat_time, options))

        (incomplete_req, incomplete_res), (complete_req, complete_res) = self._generate(buffers, last_option)

        yield incomplete_req, incomplete_res
        yield complete_req, complete_res

    def _generate(self, buffers, last_option) -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
        """
        Generate two different packets, one with and one without the last option。
        """
        incomplete = {}
        complete = {}

        for buffer in buffers:
            if buffer != buffers[-1]:
                incomplete[buffer.name] = buffer.payload
                complete[buffer.name] = buffer.payload
            else:
                incomplete[buffer.name] = buffer.payload
                buffer._push_option(last_option, strict=True)
                complete[buffer.name] = buffer.payload

        return (
            # incomplete packet, i.e., without the last option
            (
                PacketConstructor(incomplete, self._proto, 'REQUEST').get_packet().encode(codec),
                PacketConstructor(incomplete, self._proto, 'RESPONSE').get_packet().encode(codec)
            ),
            # complete packet, i.e., with the last option
            (
                PacketConstructor(complete, self._proto, 'REQUEST').get_packet().encode(codec),
                PacketConstructor(complete, self._proto, 'RESPONSE').get_packet().encode(codec)
            )
        )


class GenericRepetition(BufferConstructor):

    def __init__(self, buffer_name: str, repeat_time: int):
        super().__init__(buffer_name)

        self._repeat_time = repeat_time

    def _push_opt_content(self, content: Content, strict: bool = True) -> bool:
        if super()._push_opt_content(content=content, strict=strict):
            return True

        if strict and (content['offset'] or content['depth']):
            start_idx = int(content['offset'] or 0)
            # increase the offset by the corresponding value to skip repeated options
            start_idx = self._skip_repeated_options(offset=start_idx)
            end_idx = -1 if content['depth'] is None else start_idx + int(content['depth'])
            if end_idx != -1 and end_idx < self._buffer_length:
                logger.error(f'option [{content}] cannot be pushed into the buffer')
                return False
            self._chunks.append((start_idx, content.ascii_matches))
            self._buffer_length = start_idx + len(content.ascii_matches)
            logger.debug(
                f'successfully pushed content [{content.ascii_matches.encode(codec)}] at index [{start_idx}]')
            return True

    def _push_opt_pcre(self, pcre: Pcre, strict: bool = True):
        return super()._push_opt_pcre(pcre=pcre, strict=strict)

    def _push_opt_isdataat(self, isdata: Isdataat, strict: bool = True):
        return super()._push_opt_isdataat(isdata=isdata, strict=strict)

    @abc.abstractmethod
    def _skip_repeated_options(self, offset: int) -> int:
        """
        For a content option with an offset modifier, if there are repeated options preceding it,
        the offset value must be increased to skip over those repetitions.
        """
        pass


class OneByOneRepetition(GenericRepetition):

    def __init__(self, buffer_name: str, repeat_time: int, options: list[Option], has_rule_last_option: bool = False):
        super().__init__(buffer_name, repeat_time)

        logger.debug(f'starting one by one repetition in buffer: {buffer_name}')

        if options is not None:
            self.push_options(options, has_rule_last_option=has_rule_last_option)

    def push_options(self, options: list[Option], has_rule_last_option: bool = False) -> bool:
        for option in options:
            if has_rule_last_option and option == options[-1]:
                continue
            for t in range(self._repeat_time):
                if t == 0:
                    self._push_option(option, strict=True)
                else:
                    self._push_option(option, strict=False)
        return True

    def _skip_repeated_options(self, offset: int) -> int:
        inc_offset = offset
        fresh_data = None
        for (idx, data) in self._chunks:
            if data != fresh_data:
                fresh_data = data
            else:
                inc_offset += len(data)
        return inc_offset


class SignatureGroupRepetition(GenericRepetition):

    def __init__(self, buffer_name: str, repeat_time: int, options: list[Option], has_rule_last_option: bool = False):
        super().__init__(buffer_name, repeat_time)

        logger.debug(f'starting signature group repetition in buffer: {buffer_name}')

        if options is not None:
            self.push_options(options, has_rule_last_option=has_rule_last_option)

    def push_options(self, options: list[Option], has_rule_last_option: bool = False) -> bool:
        for t in range(self._repeat_time):
            for option in options:
                if has_rule_last_option and option == options[-1]:
                    continue
                if t == 0:
                    self._push_option(option, strict=True)
                else:
                    self._push_option(option, strict=not option == options[0])
        return True

    def _skip_repeated_options(self, offset: int) -> int:
        """
        suppose that there is no identical data in a signature group

        Note: the data generated by pcre options are different in each repetition.
        """
        # TODO: may cause a problem such that: (A__B_C)(ABC)(ABC)
        return self._buffer_length
